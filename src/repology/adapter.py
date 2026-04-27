# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-few-public-methods,too-many-branches
# pylint: disable=too-many-instance-attributes,too-many-locals
# pylint: disable=too-many-statements

"""Repology query adapter."""

import json
import pathlib
import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup

import repology.exceptions
from common.df import df_regex_filter
from common.log import LOG, LOG_SPAM
from common.utils import nix_to_repology_pkg_name, parse_version
from repology.session import DEFAULT_REPOLOGY_SESSION, REPOLOGY_REQUEST_TIMEOUT

REPOLOGY_PROJECTS_URL = "https://repology.org/projects/"
IGNORE_SBOM_PACKAGE_PATTERNS = (
    r".*\.gz",
    r".*\.patch",
    r".*\.xz",
    r".*\.bz2",
    r".*\.zip",
    r".*\.gem",
    r".*\.tgz",
    r".*\.h",
    r".*\.c",
    r".*\.diff",
    r".*\?.*",
    r".*\&.*",
)
IGNORE_SBOM_REGEX = re.compile(f"(?:{'|'.join(IGNORE_SBOM_PACKAGE_PATTERNS)})")


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


def sbom_row_classify(row):
    """Classify whether the SBOM version appears outdated."""
    if row.status == "outdated":
        return "sbom_pkg_needs_update"
    if row.status in ["devel", "unique", "newest"]:
        ver_sbom = parse_version(row.version_sbom)
        ver_repo = parse_version(row.version)
        if not ver_sbom or not ver_repo or ver_sbom < ver_repo:
            return "sbom_pkg_needs_update"
    return ""


class RepologyAdapter:
    """Query and parse Repology package data."""

    def __init__(self, session=None, request_timeout=REPOLOGY_REQUEST_TIMEOUT):
        self.session = DEFAULT_REPOLOGY_SESSION if session is None else session
        self.request_timeout = request_timeout
        self.url_projects = REPOLOGY_PROJECTS_URL
        self.processed = set()
        self.pkgs_dict = {}
        self.df = pd.DataFrame()
        self.urlq = None
        self.df_sbom = None
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

    def _sbom_fields(self):
        self.df = pd.merge(
            left=self.df_sbom,
            right=self.df,
            how="left",
            left_on=["name"],
            right_on=["package"],
            suffixes=["_sbom", ""],
        )
        self.df["version_sbom"] = self.df.pop("version_sbom")
        self.df.drop("name", axis=1, inplace=True)

    def _get_resp(self, url):
        LOG.debug("GET: %s", url)
        resp = self.session.get(url, timeout=self.request_timeout)
        LOG.debug("resp.status_code: %s", resp.status_code)
        if resp.status_code == 404:
            LOG.fatal("No matching packages found")
            raise repology.exceptions.RepologyNoMatchingPackages
        resp.raise_for_status()
        return resp

    def _parse_pkg_search_resp(self, resp, repo, pkg_stop=None):
        next_query_project = ""
        soup = BeautifulSoup(resp.text, "html.parser")
        tables = soup.find_all("table")
        if not tables:
            LOG.debug("Projects table missing: no matching packages")
            return next_query_project
        projects_table = tables[0]
        if projects_table.thead is None or projects_table.tbody is None:
            LOG.fatal("Unexpected response, malformed projects table")
            raise repology.exceptions.RepologyUnexpectedResponse
        headers = {}
        for idx, header in enumerate(projects_table.thead.find_all("th")):
            headers[header.text] = idx
        if not headers:
            LOG.fatal("Unexpected response, missing headers")
            raise repology.exceptions.RepologyUnexpectedResponse
        LOG.log(LOG_SPAM, headers)
        projects_table_rows = projects_table.tbody.find_all("tr")
        rows = 0
        stop_query = False
        for row in projects_table_rows:
            cols = row.find_all("td")
            if not cols:
                LOG.log(LOG_SPAM, "No columns on row: %s", row)
                continue
            rows += 1
            LOG.log(LOG_SPAM, "cols: %s", cols)
            pkg = cols[headers["Project"]]
            pkg_links = pkg.find_all("a")
            if not pkg_links:
                LOG.fatal("Unexpected response, missing project link")
                raise repology.exceptions.RepologyUnexpectedResponse
            pkg_name = pkg_links[0].string
            if not stop_query and pkg_stop and pkg_name == pkg_stop:
                stop_query = True
                LOG.debug("Stopping queries after parsing the current response")
            pkg_id = f"{repo}:{pkg_name}"
            if pkg_id in self.processed:
                LOG.debug("Package '%s' in search resp already processed", pkg_name)
                continue
            LOG.debug("Adding package '%s' to self.processed", pkg_name)
            self.processed.add(pkg_id)
            newest = cols[headers["Newest"]]
            nspans = newest.find_all("span", {"class": "version-newest"})
            newest_releases = []
            if nspans:
                for nspan in nspans:
                    rel_version = re.sub(r"[^\x00-\x7f]+", "", nspan.text)
                    newest_releases.append(rel_version)
            sel = cols[headers["Selected"]]
            statuses = re.findall(r'version-([^"]+)"', str(sel))
            vspans = sel.find_all("span", {"class": "version"})
            for idx, vspan in enumerate(vspans):
                ver = re.sub(r"[^\x00-\x7f]+", "", vspan.text)
                vulnerable = bool(vspan.find_all("span", {"class": "vulnerable"}))
                status = statuses[idx]
                self.pkgs_dict.setdefault("repo", []).append(repo)
                self.pkgs_dict.setdefault("package", []).append(pkg_name)
                self.pkgs_dict.setdefault("version", []).append(ver)
                self.pkgs_dict.setdefault("status", []).append(status)
                self.pkgs_dict.setdefault("potentially_vulnerable", []).append(
                    str(int(vulnerable))
                )
                self.pkgs_dict.setdefault("newest_upstream_release", []).append(
                    ";".join(newest_releases)
                )
                LOG.log(LOG_SPAM, "Added: %s:%s:%s", pkg_name, ver, status)
            if rows == 200 and not stop_query:
                next_query_project = pkg_name
        if rows > 200:
            LOG.warning(
                "Unexpected response: raising this warning to notify the "
                "possibility the repology API has changed and might no longer "
                "match what this client expects"
            )
        return next_query_project

    def _parse_sbom_cdx(self, path):
        LOG.debug("Parsing cdx sbom: %s", path)
        with open(path, encoding="utf-8") as inf:
            json_dict = json.loads(inf.read())
        metadata = json_dict.get("metadata", {})
        components = list(json_dict.get("components", []))
        if "component" in metadata:
            components.append(metadata["component"])
        components_dict = {}
        for cmp in components:
            name = nix_to_repology_pkg_name(cmp["name"])
            components_dict.setdefault("name", []).append(name)
            components_dict.setdefault("version", []).append(cmp["version"])
        if not components_dict:
            return pd.DataFrame({"name": [], "version": []})
        df_components = pd.DataFrame(components_dict)
        df_components.fillna("", inplace=True)
        df_components = df_components.astype(str)
        df_components.sort_values("name", inplace=True)
        df_components.reset_index(drop=True, inplace=True)
        return df_components

    def _query_pkg_search(self, pkg_search, repository, stop_pkg=None):
        pkg = urllib.parse.quote(pkg_search)
        repo = urllib.parse.quote(repository)
        search_term = f"?search={pkg}&inrepo={repo}"
        url = f"{self.url_projects}{search_term}"
        self.urlq = url
        while True:
            resp = self._get_resp(url)
            url_last = url
            next_query_project = self._parse_pkg_search_resp(resp, repository, stop_pkg)
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
        self.df_sbom = self._parse_sbom_cdx(query.sbom_cdx)
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
                self.pkgs_dict.setdefault("repo", []).append(query.repository)
                self.pkgs_dict.setdefault("package", []).append(cmp.name)
                self.pkgs_dict.setdefault("version", []).append("")
                self.pkgs_dict.setdefault("status", []).append("NO_VERSION")
                self.pkgs_dict.setdefault("potentially_vulnerable", []).append("")
                self.pkgs_dict.setdefault("newest_upstream_release", []).append("")
                self._packages_to_df(query, re_pkg_internal=cmp.name)
                continue
            if re.match(IGNORE_SBOM_REGEX, cmp.name):
                self.pkgs_dict.setdefault("repo", []).append(query.repository)
                self.pkgs_dict.setdefault("package", []).append(cmp.name)
                self.pkgs_dict.setdefault("version", []).append(cmp.version)
                self.pkgs_dict.setdefault("status", []).append("IGNORED")
                self.pkgs_dict.setdefault("potentially_vulnerable", []).append("")
                self.pkgs_dict.setdefault("newest_upstream_release", []).append("")
                self._packages_to_df(query, re_pkg_internal=cmp.name)
                continue
            try:
                self._query_pkg_exact(cmp.name, query.repository)
            except repology.exceptions.RepologyNoMatchingPackages:
                LOG.debug("Package '%s' not found in repology", cmp.name)
            if pkg_id not in self.processed:
                self.pkgs_dict.setdefault("repo", []).append(query.repository)
                self.pkgs_dict.setdefault("package", []).append(cmp.name)
                self.pkgs_dict.setdefault("version", []).append(cmp.version)
                self.pkgs_dict.setdefault("status", []).append("NOT_FOUND")
                self.pkgs_dict.setdefault("potentially_vulnerable", []).append("")
                self.pkgs_dict.setdefault("newest_upstream_release", []).append("")
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
            self._sbom_fields()
            self.df["sbom_version_classify"] = self.df.apply(sbom_row_classify, axis=1)
        self.df["repo_version_classify"] = self.df.apply(repo_row_classify, axis=1)
        self.df.replace(np.nan, "", regex=True, inplace=True)
        self.df.drop_duplicates(keep="first", inplace=True)
        self.df.sort_values(by=self.df.columns.values.tolist(), inplace=True)
        self.df.reset_index(drop=True, inplace=True)
        return self.df.copy(deep=True)
