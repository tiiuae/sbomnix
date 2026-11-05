#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability triage helpers."""

from requests import RequestException

from common import columns as cols
from common.df import df_log
from common.log import LOG, LOG_SPAM
from vulnxscan.evidence import EVIDENCE_REPORT_COLUMNS
from vulnxscan.github_prs import GitHubPrLookup, GitHubUnexpectedResponse
from vulnxscan.repology_lookup import RepologyVulnerabilityLookup

_DEFAULT_REPOLOGY_LOOKUP = None
_DEFAULT_GITHUB_PR_LOOKUP = None


def _get_default_repology_lookup():
    global _DEFAULT_REPOLOGY_LOOKUP  # noqa: PLW0603
    if _DEFAULT_REPOLOGY_LOOKUP is None:
        _DEFAULT_REPOLOGY_LOOKUP = RepologyVulnerabilityLookup()
    return _DEFAULT_REPOLOGY_LOOKUP


def _get_default_github_lookup():
    global _DEFAULT_GITHUB_PR_LOOKUP  # noqa: PLW0603
    if _DEFAULT_GITHUB_PR_LOOKUP is None:
        _DEFAULT_GITHUB_PR_LOOKUP = GitHubPrLookup()
    return _DEFAULT_GITHUB_PR_LOOKUP


def unavailable_triage_report(df_report, search_nix_prs):
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
    if search_nix_prs:
        columns.append(cols.NIXPKGS_PR)

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
    search_nix_prs,
    repology_lookup=None,
    github_lookup=None,
):
    """Enrich a vulnerability report with version hints and optional PRs."""
    repology_lookup = (
        _get_default_repology_lookup() if repology_lookup is None else repology_lookup
    )
    github_lookup = (
        _get_default_github_lookup() if github_lookup is None else github_lookup
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
    if search_nix_prs:
        LOG.verbose("Querying nixpkgs github PRs")
        try:
            df_vuln_pkgs[cols.NIXPKGS_PR] = df_vuln_pkgs.apply(
                github_lookup.find_nixpkgs_prs,
                axis=1,
            )
        except (RequestException, GitHubUnexpectedResponse) as error:
            # Keep the Repology version hints. Empty PRs for every row,
            # since a partial column reads as "no PRs found".
            df_vuln_pkgs[cols.NIXPKGS_PR] = ""
            LOG.warning(
                "Failed querying nixpkgs github PRs: column left empty: %s", error
            )
    sort_cols = [cols.SORTCOL, cols.PACKAGE, cols.SEVERITY, cols.VERSION_LOCAL]
    df_vuln_pkgs.sort_values(by=sort_cols, ascending=False, inplace=True)
    return df_vuln_pkgs
