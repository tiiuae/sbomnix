#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Reporting helpers for vulnxscan findings."""

import pathlib

import pandas as pd
from tabulate import tabulate

from common.df import df_from_csv_file, df_to_csv_file
from common.log import LOG, LOG_VERBOSE
from vulnxscan.utils import _is_patched, _reformat_scanner, _vuln_sortcol, _vuln_url
from vulnxscan.whitelist import df_apply_whitelist, df_drop_whitelisted, load_whitelist


def build_report_dataframe(df_vulnix, df_grype, df_osv, *, log=LOG):
    """Combine scanner findings into the final report dataframe."""
    scanner_dfs = [df for df in [df_vulnix, df_grype, df_osv] if df is not None]
    if not scanner_dfs:
        log.debug("No scanners reported any findings")
        return pd.DataFrame()
    df = pd.concat(scanner_dfs, ignore_index=True)
    if df.empty:
        log.debug("No scanners reported any findings")
        return pd.DataFrame()
    if "modified" not in df.columns:
        df["modified"] = pd.NaT
    df["sortcol"] = df.apply(_vuln_sortcol, axis=1)
    df["count"] = 1
    group_cols = ["vuln_id", "package", "severity", "version", "sortcol"]
    df = df.pivot_table(index=group_cols, columns="scanner", values="count")
    df.reset_index(drop=False, inplace=True)
    scanners = ["grype", "osv"]
    if df_vulnix is not None:
        scanners.append("vulnix")
    df.reindex(group_cols + scanners, axis=1)
    for scanner_col in scanners:
        if scanner_col not in df:
            df[scanner_col] = 0
    df["sum"] = df[scanners].sum(axis=1).astype(int)
    df["grype"] = df.apply(lambda row: _reformat_scanner(row.grype), axis=1)
    df["osv"] = df.apply(lambda row: _reformat_scanner(row.osv), axis=1)
    if "vulnix" in scanners:
        df["vulnix"] = df.apply(lambda row: _reformat_scanner(row.vulnix), axis=1)
    df["url"] = df.apply(_vuln_url, axis=1)
    sort_cols = ["sortcol", "package", "severity", "version"]
    df.sort_values(by=sort_cols, ascending=False, inplace=True)
    report_cols = (
        ["vuln_id", "url", "package", "version", "severity"]
        + scanners
        + ["sum", "sortcol"]
    )
    return df[report_cols]


def filter_patched_report(df_report, sbom_csv, *, log=LOG):
    """Filter out vulnerabilities that are marked as patched in the SBOM CSV."""
    log.log(LOG_VERBOSE, "Filtering patched vulnerabilities")
    df_sbom_csv = df_from_csv_file(sbom_csv)
    df = pd.merge(
        left=df_report,
        right=df_sbom_csv,
        how="left",
        left_on=["package", "version"],
        right_on=["pname", "version"],
        suffixes=["", "_sbom_csv"],
    )
    df["patched"] = df.apply(_is_patched, axis=1)
    df = df[~df["patched"]]
    df = df[df_report.columns.values]
    return df.drop_duplicates(keep="first")


def apply_whitelist_annotations(df_report, whitelist_csv):
    """Apply whitelist annotations in-place when a whitelist is provided."""
    if whitelist_csv is None:
        return
    df_whitelist = load_whitelist(whitelist_csv)
    if df_whitelist is None:
        return
    df_apply_whitelist(df_whitelist, df_report)


def render_console_report(df_report, *, df_triaged=None, log=LOG):
    """Render the console report for the final vulnerability dataframe."""
    log.debug("")
    if df_triaged is not None:
        df = df_triaged.copy()
        if "package_repology" in df:
            df = df.drop("package_repology", axis=1)
    else:
        df = df_report.copy()
    df = df.drop("sortcol", axis=1)
    df = df_drop_whitelisted(df)
    if df.empty:
        log.info("Whitelisted all vulnerabilities")
        return
    version_cols = [col for col in df.columns if "version" in col]
    for col in version_cols:
        df[col] = df[col].str.slice(0, 16)
    table = tabulate(
        df,
        headers="keys",
        tablefmt="orgtbl",
        numalign="center",
        showindex=False,
    )
    log.info(
        "Console report\n\n"
        "Potential vulnerabilities impacting version_local: "
        "\n\n%s\n\n",
        table,
    )


def write_reports(df_report, out_path, *, df_triaged=None):
    """Write the main CSV report and optional triage report."""
    out_path = pathlib.Path(out_path)
    df_to_csv_file(df_report, out_path.resolve().as_posix())
    if df_triaged is not None:
        parents = out_path.parents[0].resolve().as_posix()
        triage_out = f"{parents}/{out_path.stem}.triage{out_path.suffix}"
        df_to_csv_file(df_triaged, triage_out)
