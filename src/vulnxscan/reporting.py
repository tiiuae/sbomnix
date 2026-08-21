#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Reporting helpers for vulnxscan findings."""

import pathlib

from tabulate import tabulate

from common import columns as cols
from common.df import df_to_csv_file
from common.log import LOG
from vulnxscan.evidence import EVIDENCE_REPORT_COLUMNS
from vulnxscan.sarif import findings_to_sarif, write_sarif
from vulnxscan.whitelist import df_apply_whitelist, df_drop_whitelisted, load_whitelist

# Columns whose values are version strings and are truncated for display.
# Named explicitly rather than matched on a "version" substring: evidence
# counts such as `package_version_only_count` also contain that substring but
# hold integers.
_VERSION_DISPLAY_COLUMNS = (
    cols.VERSION,
    cols.VERSION_LOCAL,
    cols.VERSION_NIXPKGS,
    cols.VERSION_REPOLOGY,
    cols.VERSION_SBOM,
    cols.VERSION_UPSTREAM,
)

_CONSOLE_HIDDEN_COLUMNS = (cols.SORTCOL, *EVIDENCE_REPORT_COLUMNS)


def scanner_columns(df_vulnix):
    """Return scanner presence columns for the current scan mode."""
    scanners = ["grype", "osv"]
    if df_vulnix is not None:
        scanners.append("vulnix")
    return scanners


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
        if cols.PACKAGE_REPOLOGY in df:
            df = df.drop(cols.PACKAGE_REPOLOGY, axis=1)
    else:
        df = df_report.copy()
    df = df.drop(
        columns=[column for column in _CONSOLE_HIDDEN_COLUMNS if column in df.columns]
    )
    df = df_drop_whitelisted(df)
    if df.empty:
        log.info("Whitelisted all vulnerabilities")
        return
    for col in _VERSION_DISPLAY_COLUMNS:
        if col in df.columns:
            df[col] = df[col].astype(str).str.slice(0, 16)
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


def write_reports(  # noqa: PLR0913
    df_report,
    out_path,
    *,
    df_triaged=None,
    output_format="csv",
    evidence_document=None,
    sarif_location=None,
):
    """Write the selected main report and optional triage CSV report."""
    out_path = pathlib.Path(out_path)
    if output_format == "sarif":
        active_findings = df_drop_whitelisted(df_report.copy())
        document = findings_to_sarif(
            active_findings,
            evidence_document=evidence_document,
            triage_findings=df_triaged,
            location=sarif_location,
        )
        write_sarif(document, out_path)
    else:
        df_to_csv_file(df_report, out_path.resolve().as_posix())
    if df_triaged is not None:
        parents = out_path.parents[0].resolve().as_posix()
        suffix = ".csv" if output_format == "sarif" else out_path.suffix
        triage_out = f"{parents}/{out_path.stem}.triage{suffix}"
        df_to_csv_file(df_triaged, triage_out)
