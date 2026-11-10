#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability triage helpers."""

from common import columns as cols
from common.df import df_log
from common.log import LOG, LOG_SPAM
from vulnxscan.evidence import EVIDENCE_REPORT_COLUMNS
from vulnxscan.repology_lookup import RepologyVulnerabilityLookup

_DEFAULT_REPOLOGY_LOOKUP = None


def _get_default_repology_lookup():
    global _DEFAULT_REPOLOGY_LOOKUP  # noqa: PLW0603
    if _DEFAULT_REPOLOGY_LOOKUP is None:
        _DEFAULT_REPOLOGY_LOOKUP = RepologyVulnerabilityLookup()
    return _DEFAULT_REPOLOGY_LOOKUP


def unavailable_triage_report(df_report):
    """Return the stable triage shape without external enrichment."""
    columns = [
        cols.VULN_ID,
        cols.URL,
        cols.PACKAGE,
        cols.SEVERITY,
        cols.VERSION_LOCAL,
        cols.VERSION_NIXPKGS,
        cols.VERSION_UPSTREAM,
        cols.PACKAGE_REPOLOGY,
        cols.SORTCOL,
    ]
    if cols.WHITELIST in df_report.columns:
        columns.extend((cols.WHITELIST, cols.WHITELIST_COMMENT))
    columns.extend(
        column for column in EVIDENCE_REPORT_COLUMNS if column in df_report.columns
    )
    columns.append(cols.CLASSIFY)

    return (
        df_report.rename(columns={cols.VERSION: cols.VERSION_LOCAL})
        .reindex(columns=columns, fill_value="")
        .sort_values(
            by=[cols.SORTCOL, cols.PACKAGE, cols.SEVERITY, cols.VERSION_LOCAL],
            ascending=False,
        )
    )


def triage_vulnerabilities(
    df_report,
    repology_lookup=None,
):
    """Enrich a vulnerability report with Repology version hints."""
    repology_lookup = (
        _get_default_repology_lookup() if repology_lookup is None else repology_lookup
    )
    LOG.debug("")
    df = df_report.copy()
    uids = [
        cols.VULN_ID,
        cols.PACKAGE,
        cols.SEVERITY,
        cols.VERSION,
        cols.URL,
        cols.SORTCOL,
    ]
    if cols.WHITELIST in df.columns:
        uids.append(cols.WHITELIST)
        uids.append(cols.WHITELIST_COMMENT)
    for column in EVIDENCE_REPORT_COLUMNS:
        if column in df.columns:
            uids.append(column)
    df_vuln_pkgs = df.groupby(by=uids).size().reset_index(name=cols.COUNT)
    LOG.debug("Number of vulnerable packages: %s", df_vuln_pkgs.shape[0])
    if df_vuln_pkgs.empty:
        return df_vuln_pkgs
    df_log(df_vuln_pkgs, LOG_SPAM)
    df_vuln_pkgs = repology_lookup.query_repology_versions(df_vuln_pkgs)
    LOG.debug("Vulnerable pkgs with repology version info: %s", df_vuln_pkgs.shape[0])
    df_log(df_vuln_pkgs, LOG_SPAM)
    df_vuln_pkgs[cols.CLASSIFY] = ""
    sort_cols = [cols.SORTCOL, cols.PACKAGE, cols.SEVERITY, cols.VERSION_LOCAL]
    df_vuln_pkgs.sort_values(by=sort_cols, ascending=False, inplace=True)
    return df_vuln_pkgs
