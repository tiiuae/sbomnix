# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=attribute-defined-outside-init,too-many-instance-attributes

"""Repology query adapter."""

import pathlib
import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import numpy as np
import pandas as pd

import repology.exceptions
from common.df import df_regex_filter
from common.log import LOG
from repology.session import DEFAULT_REPOLOGY_SESSION, REPOLOGY_REQUEST_TIMEOUT

from .cves import parse_cve_html
from .projects_parser import parse_projects_search_html
from .sbom import (
    is_ignored_sbom_package,
    make_sbom_status_row,
    merge_sbom_fields,
    parse_cdx_sbom,
    sbom_row_classify,
)

REPOLOGY_PROJECTS_URL = "https://repology.org/projects/"
REPOLOGY_PROJECT_URL = "https://repology.org/project/"


@dataclass
class RepologyQuery:
    """Repology query parameters independent of the CLI parser."""

    repository: str
    pkg_exact: Optional[str] = None
    pkg_search: Optional[str] = None
    sbom_cdx: Optional[pathlib.Path] = None
    re_package: Optional[str] = None
    re_version: Optional[str] = None
    re_status: Optional[str] = None
    re_vuln: Optional[str] = None

    def __post_init__(self):
        if self.sbom_cdx and not isinstance(self.sbom_cdx, pathlib.Path):
            self.sbom_cdx = pathlib.Path(self.sbom_cdx)
        query_modes = (
            bool(self.pkg_exact),
            bool(self.pkg_search),
            self.sbom_cdx is not None,
        )
        if sum(query_modes) != 1:
            raise ValueError(
                "RepologyQuery requires exactly one of pkg_exact, "
                "pkg_search, or sbom_cdx"
            )
        if not self.repository:
            raise ValueError("RepologyQuery requires a repository name")


def repo_row_classify(row):
    """Classify repository-side version status."""
    if row.status == "outdated":
        return "repo_pkg_needs_update"
    return ""


class RepologyAdapter:
    """Query and parse Repology package data."""

    def __init__(self, session=None, request_timeout=REPOLOGY_REQUEST_TIMEOUT):
        self.session = DEFAULT_REPOLOGY_SESSION if session is None else session
        self.request_timeout = request_timeout
        self.url_projects = REPOLOGY_PROJECTS_URL
        self._reset_state()

    def _reset_state(self):
        self.processed = set()
        self.pkgs_dict = {}
        self.df = pd.DataFrame()
        self.urlq = None
        self.df_sbom = None

    def _packages_to_df(self, query, re_pkg_internal=None):
        if not self.pkgs_dict:
            return
        LOG.debug("packages in pkgs_dict: %s", len(self.pkgs_dict["package"]))
        df = pd.DataFrame.from_dict(self.pkgs_dict)
        df_cols = df.columns.values.tolist()
        if query.repository and "repo" in df_cols:
            df = df_regex_filter(df, "repo", re.escape(query.repository))
        if re_pkg_internal and "package" in df_cols:
            re_pkg_internal = f"^(?:[a-z0-9]+:)?{re.escape(re_pkg_internal)}$"
            df = df_regex_filter(df, "package", re_pkg_internal)
        if query.re_package and "package" in df_cols:
            df = df_regex_filter(df, "package", query.re_package)
        if query.re_version and "version" in df_cols:
            df = df_regex_filter(df, "version", query.re_version)
        if query.re_status and "status" in df_cols:
            df = df_regex_filter(df, "status", query.re_status)
        if query.re_vuln and "potentially_vulnerable" in df_cols:
            df = df_regex_filter(df, "potentially_vulnerable", query.re_vuln)
        self.df = pd.concat([self.df, df])
        self.df.replace(np.nan, "", regex=True, inplace=True)
        self.df.drop_duplicates(keep="first", inplace=True)
        self.df.sort_values(by=self.df.columns.values.tolist(), inplace=True)
        self.df.reset_index(drop=True, inplace=True)

    def _append_package_rows(self, package_rows):
        for package_row in package_rows:
            for key, value in package_row.items():
                self.pkgs_dict.setdefault(key, []).append(value)

    def _get_resp(self, url):
        LOG.debug("GET: %s", url)
        resp = self.session.get(url, timeout=self.request_timeout)
        LOG.debug("resp.status_code: %s", resp.status_code)
        if resp.status_code == 404:
            LOG.fatal("No matching packages found")
            raise repology.exceptions.RepologyNoMatchingPackages
        resp.raise_for_status()
        return resp

    def query_cves(self, pkg_name, pkg_version):
        """Query vulnerabilities for a single package/version pair."""
        pkg = urllib.parse.quote(pkg_name)
        ver = urllib.parse.quote(pkg_version)
        query = f"{REPOLOGY_PROJECT_URL}{pkg}/cves?version={ver}"
        LOG.debug("GET: %s", query)
        resp = self.session.get(query, timeout=self.request_timeout)
        LOG.debug("resp.status_code: %s", resp.status_code)
        if resp.status_code == 404:
            LOG.warning("Repology package '%s' not found", pkg_name)
            return None
        resp.raise_for_status()
        return parse_cve_html(resp.text, pkg_name, pkg_version)

    def _query_pkg_search(self, pkg_search, repository, stop_pkg=None):
        pkg = urllib.parse.quote(pkg_search)
        repo = urllib.parse.quote(repository)
        search_term = f"?search={pkg}&inrepo={repo}"
        url = f"{self.url_projects}{search_term}"
        self.urlq = url
        while True:
            resp = self._get_resp(url)
            url_last = url
            page = parse_projects_search_html(
                resp.text,
                repository,
                self.processed,
                pkg_stop=stop_pkg,
            )
            self.processed = page.processed_ids
            self._append_package_rows(page.package_rows)
            next_query_project = page.next_query_project
            if not next_query_project:
                LOG.debug("stopping (no next_query_project)")
                break
            next_query_project = urllib.parse.quote(next_query_project)
            url = f"{self.url_projects}{next_query_project}/{search_term}"
            if url == url_last:
                LOG.debug("stopping ('%s'=='%s')", url_last, url)
                break

    def _query_pkg_exact(self, pkg_name, repository):
        self._query_pkg_search(pkg_name, repository, stop_pkg=pkg_name)

    def _query_sbom_cdx(self, query):
        self.df_sbom = parse_cdx_sbom(query.sbom_cdx)
        for cmp in self.df_sbom.itertuples():
            LOG.debug("Package: %s", cmp)
            if not cmp.name:
                LOG.fatal("Missing package name: %s", cmp)
                raise repology.exceptions.RepologyUnexpectedResponse
            pkg_id = f"{query.repository}:{cmp.name}"
            if pkg_id in self.processed:
                LOG.debug("Package '%s' in sbom already processed", cmp.name)
                self._packages_to_df(query, re_pkg_internal=cmp.name)
                continue
            if not cmp.version:
                self._append_package_rows(
                    [
                        make_sbom_status_row(
                            query.repository,
                            cmp.name,
                            "",
                            "NO_VERSION",
                        )
                    ]
                )
                self._packages_to_df(query, re_pkg_internal=cmp.name)
                continue
            if is_ignored_sbom_package(cmp.name):
                self._append_package_rows(
                    [
                        make_sbom_status_row(
                            query.repository,
                            cmp.name,
                            cmp.version,
                            "IGNORED",
                        )
                    ]
                )
                self._packages_to_df(query, re_pkg_internal=cmp.name)
                continue
            try:
                self._query_pkg_exact(cmp.name, query.repository)
            except repology.exceptions.RepologyNoMatchingPackages:
                LOG.debug("Package '%s' not found in repology", cmp.name)
            if pkg_id not in self.processed:
                self._append_package_rows(
                    [
                        make_sbom_status_row(
                            query.repository,
                            cmp.name,
                            cmp.version,
                            "NOT_FOUND",
                        )
                    ]
                )
            self._packages_to_df(query, re_pkg_internal=cmp.name)
        self.urlq = self.url_projects

    def query(self, query):
        """Query package information from repology.org."""
        self._reset_state()
        if query.pkg_search:
            self._query_pkg_search(query.pkg_search, query.repository)
        elif query.pkg_exact:
            self._query_pkg_exact(query.pkg_exact, query.repository)
        elif query.sbom_cdx:
            self._query_sbom_cdx(query)
        self._packages_to_df(query, re_pkg_internal=query.pkg_exact)
        if self.df.empty:
            LOG.debug("No matching packages found")
            raise repology.exceptions.RepologyNoMatchingPackages
        if self.df_sbom is not None:
            self.df = merge_sbom_fields(self.df_sbom, self.df)
            self.df["sbom_version_classify"] = self.df.apply(sbom_row_classify, axis=1)
        self.df["repo_version_classify"] = self.df.apply(repo_row_classify, axis=1)
        self.df.replace(np.nan, "", regex=True, inplace=True)
        self.df.drop_duplicates(keep="first", inplace=True)
        self.df.sort_values(by=self.df.columns.values.tolist(), inplace=True)
        self.df.reset_index(drop=True, inplace=True)
        return self.df.copy(deep=True)
