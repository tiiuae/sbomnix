#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Repology-backed lookup helpers for vulnerability triage."""

from pathlib import Path

import pandas as pd

from common import columns as cols
from common.df import df_log
from common.log import LOG, LOG_SPAM
from common.package_names import nix_to_repology_pkg_name
from common.versioning import version_distance
from repology.adapter import RepologyAdapter, RepologyQuery
from repology.exceptions import RepologyNoMatchingPackages
from repology.repology_cve import query_cve


def select_newest(df):
    """Return the newest rows per package."""
    selected = []
    for pkg_name in df[cols.PACKAGE].unique():
        df_pkg = df[df[cols.PACKAGE] == str(pkg_name)]
        df_newest = df_pkg[df_pkg[cols.STATUS] == "newest"]
        if df_newest.empty:
            df_newest = df_pkg.sort_values(by=[cols.VERSION]).iloc[[-1]]
        selected.append(df_newest)
    if not selected:
        return pd.DataFrame()
    return pd.concat(selected, ignore_index=True)


def _add_triage_item(out_dict, vuln, whitelist_cols, df_repo=None):
    if df_repo is None:
        out_dict.setdefault(cols.VULN_ID, []).append(vuln.vuln_id)
        out_dict.setdefault(cols.URL, []).append(vuln.url)
        out_dict.setdefault(cols.PACKAGE, []).append(vuln.package)
        out_dict.setdefault(cols.SEVERITY, []).append(vuln.severity)
        out_dict.setdefault(cols.VERSION_LOCAL, []).append(vuln.version)
        out_dict.setdefault(cols.VERSION_NIXPKGS, []).append("")
        out_dict.setdefault(cols.VERSION_UPSTREAM, []).append("")
        out_dict.setdefault(cols.PACKAGE_REPOLOGY, []).append("")
        out_dict.setdefault(cols.SORTCOL, []).append(vuln.sortcol)
        if whitelist_cols:
            out_dict.setdefault(cols.WHITELIST, []).append(vuln.whitelist)
            out_dict.setdefault(cols.WHITELIST_COMMENT, []).append(
                vuln.whitelist_comment
            )
        return
    for item in df_repo.itertuples():
        out_dict.setdefault(cols.VULN_ID, []).append(vuln.vuln_id)
        out_dict.setdefault(cols.URL, []).append(vuln.url)
        out_dict.setdefault(cols.PACKAGE, []).append(vuln.package)
        out_dict.setdefault(cols.SEVERITY, []).append(vuln.severity)
        out_dict.setdefault(cols.VERSION_LOCAL, []).append(vuln.version)
        out_dict.setdefault(cols.VERSION_NIXPKGS, []).append(item.version)
        if item.newest_upstream_release and ";" in item.newest_upstream_release:
            version_upstream_str = item.newest_upstream_release.split(";")[0]
        else:
            version_upstream_str = item.newest_upstream_release
        out_dict.setdefault(cols.VERSION_UPSTREAM, []).append(version_upstream_str)
        out_dict.setdefault(cols.PACKAGE_REPOLOGY, []).append(item.package)
        out_dict.setdefault(cols.SORTCOL, []).append(vuln.sortcol)
        if whitelist_cols:
            out_dict.setdefault(cols.WHITELIST, []).append(vuln.whitelist)
            out_dict.setdefault(cols.WHITELIST_COMMENT, []).append(
                vuln.whitelist_comment
            )


def _version_similarity(row):
    ratio = version_distance(row.version, row.version_cmp)
    LOG.log(
        LOG_SPAM,
        "Version similarity ('%s' vs '%s' ==> %s)",
        row.version,
        row.version_cmp,
        ratio,
    )
    return ratio


class RepologyVulnerabilityLookup:
    """Cache and query Repology/CVE data used by triage."""

    def __init__(self, adapter=None, cve_query=None):
        self.adapter = RepologyAdapter() if adapter is None else adapter
        self.cve_query = query_cve if cve_query is None else cve_query
        self._repology_cve_dfs = {}
        self._repology_dfs = {}

    def is_vulnerable(self, repo_pkg_name, pkg_version, cve_id=None):
        """
        Return true if given pkg version is vulnerable. If ``cve_id`` is
        specified, return true only if pkg is affected by the given cve id.
        """
        LOG.debug("Finding vulnerability status for %s:%s", repo_pkg_name, pkg_version)
        key = f"{repo_pkg_name}:{pkg_version}"
        if key in self._repology_cve_dfs:
            LOG.log(LOG_SPAM, "Using cached repology_cve results")
            df = self._repology_cve_dfs[key]
        else:
            df = self.cve_query(str(repo_pkg_name), str(pkg_version))
            if df is None:
                df = pd.DataFrame()
            df_log(df, LOG_SPAM)
            self._repology_cve_dfs[key] = df
        if cve_id and not df.empty:
            df = df[df["cve"] == cve_id]
        return not df.empty

    def query_repology(self, pname, match_type="pkg_exact"):
        """Return cached Repology results for a package name."""
        LOG.log(LOG_SPAM, "Querying repology for '%s'", pname)
        cache_key = f"{match_type}:{pname}"
        if cache_key in self._repology_dfs:
            LOG.log(LOG_SPAM, "Using cached repology results")
            return self._repology_dfs[cache_key].copy(deep=True)
        if match_type == "pkg_search":
            query = RepologyQuery(
                repository="nix_unstable",
                pkg_search=pname,
                re_status="outdated|newest|devel|unique",
            )
        elif match_type == "sbom_cdx":
            query = RepologyQuery(
                repository="nix_unstable",
                sbom_cdx=Path(pname),
                re_status="outdated|newest|devel|unique",
            )
        elif match_type == "pkg_exact":
            query = RepologyQuery(
                repository="nix_unstable",
                pkg_exact=pname,
                re_status="outdated|newest|devel|unique",
            )
        else:
            raise ValueError(f"Unknown match_type: {match_type!r}")
        try:
            df_repology = self.adapter.query(query)
        except RepologyNoMatchingPackages:
            df_repology = None
        if df_repology is None or df_repology.empty:
            LOG.debug("No results from repology")
            return None
        df_repology = select_newest(df_repology)
        self._repology_dfs[cache_key] = df_repology.copy(deep=True)
        df_log(df_repology, LOG_SPAM)
        return df_repology

    def query_repology_versions(self, df_vuln_pkgs):
        """Augment vulnerable package rows with Repology version data."""
        LOG.verbose("Querying repology")
        result_dict = {}
        whitelist_cols = cols.WHITELIST in df_vuln_pkgs.columns
        for vuln in df_vuln_pkgs.itertuples():
            if whitelist_cols and vuln.whitelist:
                LOG.log(LOG_SPAM, "Whitelisted, skipping repology query: %s", vuln)
                _add_triage_item(result_dict, vuln, whitelist_cols)
                continue
            repo_pkg = nix_to_repology_pkg_name(vuln.package)
            LOG.log(LOG_SPAM, "Package '%s' ==> '%s'", vuln.package, repo_pkg)
            df_repology = self.query_repology(repo_pkg)
            if df_repology is None or df_repology.empty:
                _add_triage_item(result_dict, vuln, whitelist_cols)
                continue
            if df_repology.shape[0] == 1:
                LOG.log(LOG_SPAM, "One repology package matches")
                _add_triage_item(result_dict, vuln, whitelist_cols, df_repology)
                continue
            df_exact = df_repology[df_repology[cols.VERSION] == vuln.version]
            if not df_exact.empty:
                LOG.log(LOG_SPAM, "Exact version match '%s'", vuln.version)
                _add_triage_item(result_dict, vuln, whitelist_cols, df_exact)
                continue
            df_repology = df_repology.copy(deep=True)
            df_repology[cols.VERSION_CMP] = vuln.version
            df_repology[cols.SIMILARITY] = df_repology.apply(
                _version_similarity,
                axis=1,
            )
            df_similar = df_repology[df_repology[cols.SIMILARITY] >= 0.7]
            if not df_similar.empty:
                LOG.log(LOG_SPAM, "Version similarity match:\n%s", df_similar)
                best_match = df_similar[cols.SIMILARITY].max()
                df_similar = df_similar[df_similar[cols.SIMILARITY] == best_match]
                LOG.log(
                    LOG_SPAM,
                    "Selecting best match based on version:\n%s",
                    df_similar,
                )
                _add_triage_item(result_dict, vuln, whitelist_cols, df_similar)
                continue
            LOG.log(LOG_SPAM, "Vague match in repology pkg, adding vuln only")
            _add_triage_item(result_dict, vuln, whitelist_cols)
        df_result = pd.DataFrame(result_dict)
        df_result.fillna("", inplace=True)
        df_result.reset_index(drop=True, inplace=True)
        return df_result
