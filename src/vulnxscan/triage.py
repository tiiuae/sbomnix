#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-return-statements

"""Vulnerability triage helpers."""

from common.df import df_log
from common.log import LOG, LOG_SPAM
from common.versioning import parse_version
from vulnxscan.github_prs import GitHubPrLookup
from vulnxscan.repology_lookup import RepologyVulnerabilityLookup

_DEFAULT_REPOLOGY_LOOKUP = None
_DEFAULT_GITHUB_PR_LOOKUP = None


def _get_default_repology_lookup():
    global _DEFAULT_REPOLOGY_LOOKUP  # pylint: disable=global-statement
    if _DEFAULT_REPOLOGY_LOOKUP is None:
        _DEFAULT_REPOLOGY_LOOKUP = RepologyVulnerabilityLookup()
    return _DEFAULT_REPOLOGY_LOOKUP


def _get_default_github_lookup():
    global _DEFAULT_GITHUB_PR_LOOKUP  # pylint: disable=global-statement
    if _DEFAULT_GITHUB_PR_LOOKUP is None:
        _DEFAULT_GITHUB_PR_LOOKUP = GitHubPrLookup()
    return _DEFAULT_GITHUB_PR_LOOKUP


def classify_vulnerability(row, repology_lookup=None):
    """Classify a vulnerable package row using Repology/CVE data."""
    repology_lookup = (
        _get_default_repology_lookup() if repology_lookup is None else repology_lookup
    )
    if not row.version_nixpkgs and not row.version_upstream:
        return "err_missing_repology_version"
    if row.version_local and not repology_lookup.is_vulnerable(
        row.package_repology, row.version_local, row.vuln_id
    ):
        return "err_not_vulnerable_based_on_repology"
    version_local = parse_version(row.version_local)
    version_nixpkgs = parse_version(row.version_nixpkgs)
    if not version_local or not version_nixpkgs:
        return "err_invalid_version"
    if row.version_nixpkgs and version_local < version_nixpkgs:
        if not repology_lookup.is_vulnerable(
            row.package_repology, row.version_nixpkgs, row.vuln_id
        ):
            return "fix_update_to_version_nixpkgs"
    version_upstream = parse_version(row.version_upstream)
    if not version_upstream:
        return "err_invalid_version"
    if row.version_upstream and version_local < version_upstream:
        if not repology_lookup.is_vulnerable(
            row.package_repology, version_upstream, row.vuln_id
        ):
            return "fix_update_to_version_upstream"
    return "fix_not_available"


def triage_vulnerabilities(
    df_report,
    search_nix_prs,
    repology_lookup=None,
    github_lookup=None,
):
    """Enrich and classify a vulnerability report."""
    repology_lookup = (
        _get_default_repology_lookup() if repology_lookup is None else repology_lookup
    )
    github_lookup = (
        _get_default_github_lookup() if github_lookup is None else github_lookup
    )
    LOG.debug("")
    df = df_report.copy()
    uids = ["vuln_id", "package", "severity", "version", "url", "sortcol"]
    if "whitelist" in df.columns:
        uids.append("whitelist")
        uids.append("whitelist_comment")
    df_vuln_pkgs = df.groupby(by=uids).size().reset_index(name="count")
    LOG.debug("Number of vulnerable packages: %s", df_vuln_pkgs.shape[0])
    if df_vuln_pkgs.empty:
        return df_vuln_pkgs
    df_log(df_vuln_pkgs, LOG_SPAM)
    df_vuln_pkgs = repology_lookup.query_repology_versions(df_vuln_pkgs)
    LOG.debug("Vulnerable pkgs with repology version info: %s", df_vuln_pkgs.shape[0])
    df_log(df_vuln_pkgs, LOG_SPAM)
    df_vuln_pkgs["classify"] = df_vuln_pkgs.apply(
        lambda row: classify_vulnerability(row, repology_lookup=repology_lookup),
        axis=1,
    )
    if search_nix_prs:
        LOG.verbose("Querying nixpkgs github PRs")
        df_vuln_pkgs["nixpkgs_pr"] = df_vuln_pkgs.apply(
            github_lookup.find_nixpkgs_prs,
            axis=1,
        )
    sort_cols = ["sortcol", "package", "severity", "version_local"]
    df_vuln_pkgs.sort_values(by=sort_cols, ascending=False, inplace=True)
    return df_vuln_pkgs
