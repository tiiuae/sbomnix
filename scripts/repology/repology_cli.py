#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name, import-error, unexpected-keyword-arg,
# pylint: disable=abstract-method, too-few-public-methods
# pylint: disable=too-many-instance-attributes, too-many-locals,

""" Command-line interface to repology.org """

import logging
import os
import sys
import pathlib
import json
import re
import urllib.parse
from argparse import ArgumentParser, ArgumentTypeError, SUPPRESS
from requests import Session
from requests_cache import CacheMixin
from requests_ratelimiter import LimiterMixin
from bs4 import BeautifulSoup
import numpy as np
import pandas as pd
from tabulate import tabulate
from sbomnix.utils import (
    setup_logging,
    LOGGER_NAME,
    LOG_SPAM,
    df_to_csv_file,
    df_regex_filter,
)

###############################################################################

_LOG = logging.getLogger(LOGGER_NAME)

###############################################################################


def _pkg_str(str_obj):
    if isinstance(str_obj, str) and len(str_obj) > 0:
        return str_obj
    raise ArgumentTypeError("Value must be a non-empty string")


def getargs():
    """Parse command line arguments"""
    desc = "Command line client to query repology.org for package information."
    epil = (
        f"Example: ./{os.path.basename(__file__)} --pkg_search 'firef' "
        " --repository 'nix_unstable'"
    )
    parser = ArgumentParser(description=desc, epilog=epil, add_help=False)
    required = parser.add_argument_group(
        "Required arguments",
        "Following arguments are mutually exclusive:",
    )
    exclusiveq = required.add_mutually_exclusive_group(required=True)
    requiredo = parser.add_argument_group("Required other arguments")
    filtergr = parser.add_argument_group(
        "Optional output filter arguments (regular expressions)"
    )
    optional = parser.add_argument_group("Optional other arguments")
    helps = "Show this help message and exit"
    optional.add_argument("-h", "--help", action="help", default=SUPPRESS, help=helps)
    # Arguments that impact repology.org queries:
    helps = "Package name exact match (see: https://repology.org/projects/)"
    exclusiveq.add_argument("--pkg_exact", help=helps, type=_pkg_str)
    helps = "Package name search term (see: https://repology.org/projects/)"
    exclusiveq.add_argument("--pkg_search", help=helps, type=_pkg_str)
    helps = "Read the package names and versions from the given cdx SBOM"
    exclusiveq.add_argument("--sbom_cdx", help=helps, type=pathlib.Path)
    helps = "Repository name exact match (see: https://repology.org/repositories)"
    requiredo.add_argument(
        "--repository", required=True, help=helps, type=str, default=""
    )
    # Arguments that impact output results:
    helps = "Filter reported results based on package name"
    filtergr.add_argument("-p", "--re_package", help=helps, type=str, default=None)
    helps = "Filter reported results based on version string"
    filtergr.add_argument("-v", "--re_version", help=helps, type=str, default=None)
    helps = "Filter reported results based on status string"
    filtergr.add_argument("-s", "--re_status", help=helps, type=str, default=None)
    helps = "Filter reported results based on vulnerability status"
    filtergr.add_argument("-c", "--re_vuln", help=helps, type=str, default=None)
    # Other arguments:
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    optional.add_argument("--verbose", help=helps, type=int, default=1)
    helps = "Path to output report file (default: ./repology_report.csv)"
    optional.add_argument("--out", help=helps, default="repology_report.csv")
    return parser.parse_args()


################################################################################


class CachedLimiterSession(CacheMixin, LimiterMixin, Session):
    """Session class with caching and rate-limiting"""

    # See: https://requests-cache.readthedocs.io/en/stable/user_guide/compatibility.html


class Repology:
    """Query and parse Repology package data"""

    def __init__(self):
        self.processed = set()
        self.pkgs_dict = {}
        self.df = pd.DataFrame()
        self.urlq = None
        self.df_sbom = None
        # We don't use the v1 api endpoints (https://repology.org/api/v1) as it
        # seems there is no effective way to query the API for all the
        # datapoints we need: (repo, package, version, status,
        # vulnerability info, newest_releases). We left a draft
        # implementation of a version of this client that makes use of the
        # repology.org v1 api in the git commit history, so it would be possible
        # to later rework on it if necessary.
        # For now, we scrape the information from the following endpoint
        # instead:
        self.url_projects = "https://repology.org/projects/"
        # Comply with the "terms of use" in https://repology.org/api:
        # - Limit non-cached requests to 1 request per second
        # - Identify this client with custom user-agent
        # In addition:
        # - Cache all responses locally for 3600 seconds
        self.session = CachedLimiterSession(per_second=1, expire_after=3600)
        ua_product = "repology_cli/0"
        ua_comment = "(https://github.com/tiiuae/sbomnix)"
        self.headers = {"User-Agent": f"{ua_product} {ua_comment}"}

    def _packages_to_df(self, args, re_pkg_internal=None):
        if not self.pkgs_dict:
            return
        _LOG.debug("packages in pkgs_dict: %s", len(self.pkgs_dict["package"]))
        # Get DataFrame, drop duplicates, sort
        df = pd.DataFrame.from_dict(self.pkgs_dict)
        df_cols = df.columns.values.tolist()
        # Filter by repository name
        if args.repository and "repo" in df_cols:
            df = df_regex_filter(df, "repo", re.escape(args.repository))
        if re_pkg_internal and "package" in df_cols:
            re_pkg_internal = f"^{re.escape(re_pkg_internal)}$"
            df = df_regex_filter(df, "package", re_pkg_internal)
        # Filter by the regex filters from command line args
        if args.re_package and "package" in df_cols:
            df = df_regex_filter(df, "package", args.re_package)
        if args.re_version and "version" in df_cols:
            df = df_regex_filter(df, "version", args.re_version)
        if args.re_status and "status" in df_cols:
            df = df_regex_filter(df, "status", args.re_status)
        if args.re_vuln and "potentially_vulnerable" in df_cols:
            df = df_regex_filter(df, "potentially_vulnerable", args.re_vuln)
        self.df = pd.concat([self.df, df])
        self.df.replace(np.nan, "", regex=True, inplace=True)
        self.df.drop_duplicates(keep="first", inplace=True)
        self.df.sort_values(by=self.df.columns.values.tolist(), inplace=True)

    def _sbom_fields(self):
        # Merge self.df with self.df_sbom to get the version_sbom column
        self.df = self.df.merge(
            self.df_sbom,
            how="left",
            left_on=["package"],
            right_on=["name"],
            suffixes=["", "_sbom"],
        )
        # Drop the "name" column which is a duplicate to "package"
        self.df.drop("name", axis=1, inplace=True)

    def _get_resp(self, query):
        _LOG.info("GET: %s", query)
        resp = self.session.get(query, headers=self.headers)
        _LOG.debug("resp.status_code: %s", resp.status_code)
        if resp.status_code == 404:
            _LOG.fatal("No matching packages found")
            sys.exit(1)
        resp.raise_for_status()
        return resp

    def _report(self, args):
        """Generate result report to console and to csv file"""
        if self.df.empty:
            _LOG.warning("No matching packages found")
            sys.exit(1)
        if self.df_sbom is not None:
            self._sbom_fields()
        # Copy the df to only make changes to the console report
        df = self.df.copy(deep=True)
        # Remove rows we don't want to print to the console report
        df = df[~df.status.isin(["IGNORED", "NO_VERSION"])]
        df = df.drop_duplicates(keep="first")
        # Write the console report
        table = tabulate(
            df,
            headers="keys",
            tablefmt="orgtbl",
            numalign="center",
            showindex=False,
        )
        _LOG.info(
            "Repology package info, packages:%s\n\n%s\n\n"
            "For more details, see: %s\n",
            df.shape[0],
            table,
            self.urlq,
        )
        # Write the full report to csv file
        df_to_csv_file(self.df, args.out)

    def _parse_pkg_search_resp(self, resp, repo, pkg_stop=None):
        next_query_project = ""
        soup = BeautifulSoup(resp.text, "html.parser")
        tables = soup.find_all("table")
        if not tables:
            _LOG.debug("Projects table missing: no matching packages")
            return next_query_project
        projects_table = tables[0]
        headers = {}
        for idx, header in enumerate(projects_table.thead.find_all("th")):
            headers[header.text] = idx
        if not headers:
            _LOG.fatal("Unexpected response")
            sys.exit(1)
        _LOG.log(LOG_SPAM, headers)
        projects_table_rows = projects_table.tbody.find_all("tr")
        stop_query = False
        for row in projects_table_rows:
            cols = row.find_all("td")
            if not cols:
                _LOG.log(LOG_SPAM, "No columns on row: %s", row)
                continue
            _LOG.log(LOG_SPAM, "cols: %s", cols)
            pkg = cols[headers["Project"]]
            pkg_name = pkg.find_all("a")[0].string
            # Stop further queries if any package name matches pkg_stop
            stop_query = bool(not stop_query and pkg_stop and pkg_name == pkg_stop)
            pkg_id = f"{repo}:{pkg_name}"
            if pkg_id in self.processed:
                _LOG.debug("Package '%s' in search resp already processed", pkg_name)
                continue
            _LOG.debug("Adding package '%s' to self.processed", pkg_name)
            self.processed.add(pkg_id)
            # Extract newest release versions
            newest = cols[headers["Newest"]]
            nspans = newest.find_all("span", {"class": "version-newest"})
            newest_releases = []
            if nspans:
                for nspan in nspans:
                    # Extract version number removing non-ascii characters
                    rel_version = re.sub(r"[^\x00-\x7f]+", "", nspan.text)
                    newest_releases.append(rel_version)
            # Extract 'selected' package version
            sel = cols[headers["Selected"]]
            statuses = re.findall(r'version-([^"]+)"', str(sel))
            vspans = sel.find_all("span", {"class": "version"})
            for idx, vspan in enumerate(vspans):
                # Extract version number removing non-ascii characters
                version = re.sub(r"[^\x00-\x7f]+", "", vspan.text)
                # Package version vulnerability status
                vulnerable = bool(vspan.find_all("span", {"class": "vulnerable"}))
                # Package version status information
                status = statuses[idx]
                # Collect results
                self.pkgs_dict.setdefault("repo", []).append(repo)
                self.pkgs_dict.setdefault("package", []).append(pkg_name)
                self.pkgs_dict.setdefault("version", []).append(version)
                self.pkgs_dict.setdefault("status", []).append(status)
                self.pkgs_dict.setdefault("potentially_vulnerable", []).append(
                    str(int(vulnerable))
                )
                self.pkgs_dict.setdefault("newest_upstream_release", []).append(
                    ";".join(newest_releases)
                )
            # API returns at most 200 projects per one request. If the number
            # or returned projects is 200, we know we need to make another
            # query starting from the last returned project, for more details,
            # see: https://repology.org/api
            if len(projects_table_rows) == 200 and not stop_query:
                next_query_project = pkg_name
        return next_query_project

    def _parse_sbom_cdx(self, path):
        _LOG.debug("Parsing cdx sbom: %s", path)
        with open(path, encoding="utf-8") as inf:
            json_dict = json.loads(inf.read())
            components = []
            if "component" in json_dict["metadata"]:
                components = [json_dict["metadata"]["component"]]
            components = json_dict["components"] + components
            components_dict = {}
            for cmp in components:
                name = cmp["name"]
                # Fix sbom package name so it matches repology package name
                match = re.match(r"python[^-]*-(?P<pname>.+)", name)
                if match:
                    name = f"python:{match.group('pname')}"
                elif not match:
                    match = re.match(r"perl[^-]*-(?P<pname>.+)", name)
                    if match:
                        name = f"perl:{match.group('pname')}"
                if name == "python3":
                    name = "python"
                components_dict.setdefault("name", []).append(name)
                components_dict.setdefault("version", []).append(cmp["version"])
            df_components = pd.DataFrame(components_dict)
            df_components.fillna("", inplace=True)
            df_components = df_components.astype(str)
            df_components["name"] = df_components["name"].str.lower()
            df_components.sort_values("name", inplace=True)
            df_components.reset_index(drop=True, inplace=True)
            return df_components

    def _query_pkg_search(self, args, stop_pkg=None):
        """Query repology.org/projects/"""
        pkg = urllib.parse.quote(args.pkg_search)
        repo = urllib.parse.quote(args.repository)
        search_term = f"?search={pkg}&inrepo={repo}"
        query = f"{self.url_projects}{search_term}"
        self.urlq = query
        while True:
            resp = self._get_resp(query)
            query_last = query
            next_query_project = self._parse_pkg_search_resp(
                resp, args.repository, stop_pkg
            )
            if not next_query_project:
                _LOG.debug("stopping (no next_query_project)")
                break
            next_query_project = urllib.parse.quote(next_query_project)
            query = f"{self.url_projects}{next_query_project}/{search_term}"
            if query == query_last:
                _LOG.debug("stopping ('%s'=='%s')", query_last, query)
                break

    def _query_pkg_exact(self, args):
        """Query exact pkg match"""
        # Search pkg_exact, stop after first query response
        args.pkg_search = args.pkg_exact
        self._query_pkg_search(args, stop_pkg=args.pkg_exact)

    def _query_sbom_cdx(self, args):
        """Query repology.org based on packages in cdx sbom"""
        # Ignore the sbom packages whose name match any of the following
        ignore_sbom_pkg_names = [
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
        ]
        ignore_regexes = f"(?:{'|'.join(ignore_sbom_pkg_names)})"
        _LOG.debug("ignore_regexes: %s", ignore_regexes)
        self.df_sbom = self._parse_sbom_cdx(args.sbom_cdx.as_posix())
        for cmp in self.df_sbom.itertuples():
            _LOG.debug("Package: %s", cmp)
            if not cmp.name:
                _LOG.fatal("Missing package name: %s", cmp)
                sys.exit(1)
            if re.match(ignore_regexes, cmp.name):
                # Remove the below comments to output ignored packages:
                self.pkgs_dict.setdefault("repo", []).append(args.repository)
                self.pkgs_dict.setdefault("package", []).append(cmp.name)
                self.pkgs_dict.setdefault("version", []).append("")
                self.pkgs_dict.setdefault("status", []).append("IGNORED")
                self.pkgs_dict.setdefault("potentially_vulnerable", []).append("")
                self.pkgs_dict.setdefault("newest_upstream_release", []).append("")
                self._packages_to_df(args, re_pkg_internal=cmp.name)
                continue
            pkg_id = f"{args.repository}:{cmp.name}"
            if pkg_id in self.processed:
                _LOG.debug("Package '%s' in sbom already processed", cmp.name)
                continue
            if not cmp.version:
                # Remove the below comments to output packages with no version:
                self.pkgs_dict.setdefault("repo", []).append(args.repository)
                self.pkgs_dict.setdefault("package", []).append(cmp.name)
                self.pkgs_dict.setdefault("version", []).append("")
                self.pkgs_dict.setdefault("status", []).append("NO_VERSION")
                self.pkgs_dict.setdefault("potentially_vulnerable", []).append("")
                self.pkgs_dict.setdefault("newest_upstream_release", []).append("")
                self._packages_to_df(args, re_pkg_internal=cmp.name)
                continue
            args.pkg_exact = cmp.name
            self._query_pkg_exact(args)
            if pkg_id not in self.processed:
                self.pkgs_dict.setdefault("repo", []).append(args.repository)
                self.pkgs_dict.setdefault("package", []).append(cmp.name)
                self.pkgs_dict.setdefault("version", []).append("")
                self.pkgs_dict.setdefault("status", []).append("NOT_FOUND")
                self.pkgs_dict.setdefault("potentially_vulnerable", []).append("")
                self.pkgs_dict.setdefault("newest_upstream_release", []).append("")
            self._packages_to_df(args, re_pkg_internal=cmp.name)
        self.urlq = self.url_projects

    def query(self, args):
        """Query package information from repology.org"""
        if args.pkg_search:
            self._query_pkg_search(args)
        elif args.pkg_exact:
            self._query_pkg_exact(args)
        elif args.sbom_cdx:
            self._query_sbom_cdx(args)
        self._packages_to_df(args, re_pkg_internal=args.pkg_exact)
        self._report(args)


################################################################################


def main():
    """main entry point"""
    args = getargs()
    setup_logging(args.verbose)
    repology = Repology()
    repology.query(args)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
