#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name, import-error, unexpected-keyword-arg,
# pylint: disable=abstract-method, too-few-public-methods,
# pylint: disable=too-many-instance-attributes

""" Demonstrate querying repology api from command-line """

import logging
import os
import sys
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
    df_log,
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
    desc = (
        "Command line client to query repology.org for package information "
        "across various software repositories."
    )
    epil = f"Example: ./{os.path.basename(__file__)} --pkg 'firefox' -r 'nix'"
    parser = ArgumentParser(description=desc, epilog=epil, add_help=False)
    requiredq = parser.add_argument_group(
        "Required query arguments",
        "Following arguments mutually exclusive:",
    )
    exclusiveq = requiredq.add_mutually_exclusive_group(required=True)
    optionalq = parser.add_argument_group("Optional query arguments")
    filtergr = parser.add_argument_group(
        "Optional output filter arguments (regular expressions)"
    )
    optional = parser.add_argument_group("Optional other arguments")
    helps = "Show this help message and exit"
    optional.add_argument("-h", "--help", action="help", default=SUPPRESS, help=helps)
    # Arguments that impact repology.org queries:
    helps = "Package name search term (see: https://repology.org/projects/?search=)"
    exclusiveq.add_argument("--pkg_search", help=helps, type=_pkg_str)
    helps = "Package name exact match"
    exclusiveq.add_argument("--pkg", help=helps, type=_pkg_str)
    helps = "Repository name exact match (see: https://repology.org/repositories)"
    optionalq.add_argument("--repository", help=helps, type=str, default="")
    helps = "Add 'potentially_vulnerable' column to the report"
    optionalq.add_argument("--vuln_info", help=helps, action="store_true")
    # Arguments that impact output results:
    helps = "Filter reported results based on repository name"
    filtergr.add_argument("-r", "--re_repo", help=helps, type=str, default=None)
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
        self.packages_dict = {}
        self.urlq = None
        self.url_api_projects = "https://repology.org/api/v1/projects/"
        self.url_api_project = "https://repology.org/api/v1/project/"
        self.url_projects = "https://repology.org/projects/"
        self.url_project = "https://repology.org/project/"
        # Comply with the "terms of use" in https://repology.org/api:
        # - Limit non-cached requests to 1 requests per second
        # - Identify repology_cli with custom user-agent
        # In addition:
        # - Cache all responses for 3600 seconds
        self.session = CachedLimiterSession(per_second=1, expire_after=3600)
        ua_product = "repology_cli/0"
        ua_comment = "(https://github.com/tiiuae/sbomnix)"
        self.headers = {"User-Agent": f"{ua_product} {ua_comment}"}

    def _get_resp(self, query):
        _LOG.info("GET: %s", query)
        resp = self.session.get(query, headers=self.headers)
        _LOG.debug("resp.status_code: %s", resp.status_code)
        resp.raise_for_status()
        return resp

    def _parse_api_response(self, resp_json):
        pkg_names = list(resp_json.keys())
        pkg_names.sort()
        setcol = self.packages_dict.setdefault
        for pname in resp_json:
            _LOG.log(LOG_SPAM, "pname: %s", pname)
            for package in resp_json[pname]:
                setcol("repo", []).append(package.get("repo", ""))
                setcol("package", []).append(pname)
                setcol("version", []).append(package.get("version", ""))
                setcol("status", []).append(package.get("status", ""))
        return pkg_names

    def _query_potentially_vulnerable(self, df):
        # There is apparently no way to get package's vulnerability info
        # using the repology API. Therefore, this function scrapes the
        # package's vulnerability info from the html page at:
        # https://repology.org/project/PACKAGE_NAME/cves?version=VERSION

        # Get unique combination of following column values (packages)
        group_by_cols = ["package", "version"]
        df_pkgs = df.groupby(group_by_cols).size().reset_index(name="count")
        df_log(df_pkgs, logging.DEBUG)
        max_queries = 100
        if df_pkgs.shape[0] > max_queries:
            _LOG.warning(
                "Skipping vulnerable package query as it would require "
                "more than %s requests to repology.org",
                max_queries,
            )
            return df
        # Scrape the vulnerability status
        vuln_col = []
        for pkg in df_pkgs.itertuples():
            query = f"{self.url_project}{pkg.package}/cves?version={pkg.version}"
            resp = self._get_resp(query)
            soup = BeautifulSoup(resp.text, "html.parser")
            tables = soup.find_all("table")
            if not tables:
                vuln_col.append(int(False))
            else:
                span = tables[0].find_all("span", {"class": "version version-outdated"})
                _LOG.log(LOG_SPAM, span)
                vuln_col.append(int(bool(span)))
        df_pkgs["potentially_vulnerable"] = vuln_col
        # Merge with df to add the 'potentially_vulnerable' column to original data
        cols = group_by_cols + ["potentially_vulnerable"]
        return df.merge(df_pkgs[cols], how="left").astype(str)

    def _report(self, args):
        """Generate result report to console and to csv file"""
        # Get DataFrame, drop duplicates, sort
        df = pd.DataFrame.from_dict(self.packages_dict)
        df.replace(np.nan, "", regex=True, inplace=True)
        df.drop_duplicates(keep="first", inplace=True)
        df_cols = df.columns.values.tolist()
        df.sort_values(by=df_cols, inplace=True)

        # Repology API repo search requests (with 'inrepo' query string)
        # return packages that are in the requested repository, but the
        # response includes matching packages from from all other repositories
        # too. Below, we filter out packages from other repositories
        # to not confuse the user:
        if args.repository and "repo" in df_cols:
            df = df_regex_filter(df, "repo", args.repository)

        # Filter by the regex filters from command line args
        if args.re_repo and "repo" in df_cols:
            df = df_regex_filter(df, "repo", args.re_repo)
        if args.re_package and "package" in df_cols:
            df = df_regex_filter(df, "package", args.re_package)
        if args.re_version and "version" in df_cols:
            df = df_regex_filter(df, "version", args.re_version)
        if args.re_status and "status" in df_cols:
            df = df_regex_filter(df, "status", args.re_status)
        if not df.empty and args.vuln_info:
            # Query potentially vulnerable packages
            df = self._query_potentially_vulnerable(df)
            df_cols = df.columns.values.tolist()
        if args.re_vuln and "potentially_vulnerable" in df_cols:
            df = df_regex_filter(df, "potentially_vulnerable", args.re_vuln)
        if df.empty:
            _LOG.warning("No matching packages found")
            sys.exit(1)
        # Write the console report
        table = tabulate(
            df, headers="keys", tablefmt="orgtbl", numalign="center", showindex=False
        )
        _LOG.info(
            "Console report\n\n%s\n\nFor more details, see: %s\n", table, self.urlq
        )
        # Write the report to csv file
        df_to_csv_file(df, args.out)

    def _query_pkg_search(self, args):
        """Query using repology api/v1/projects/"""
        search_term = f"?search={args.pkg_search}&inrepo={args.repository}"
        query = f"{self.url_api_projects}{search_term}"
        self.urlq = f"{self.url_projects}{search_term}"
        while True:
            resp_json = self._get_resp(query).json()
            query_last = query
            pkg_names = self._parse_api_response(resp_json)
            number_of_packages = len(pkg_names)
            _LOG.debug("number_of_packages: %s", number_of_packages)
            _LOG.debug("pkg_names: %s", pkg_names)
            # API returns at most 200 projects per one request, therefore,
            # we know we got all the matches if the response includes less than
            # 200 packages.
            if number_of_packages < 200:
                _LOG.debug("stopping (number_of_packages=%s)", number_of_packages)
                break
            # Otherwise, we need to make another query starting from the
            # last returned project, for details, see: https://repology.org/api
            last_project = pkg_names[-1]
            query = f"{self.url_api_projects}{last_project}/{search_term}"
            if query == query_last:
                _LOG.debug("stopping ('%s'=='%s')", query_last, query)
                break

    def _query_pkg_exact(self, args):
        """Query using repology api/v1/project/"""
        search_term = f"{args.pkg}"
        query = f"{self.url_api_project}{search_term}"
        self.urlq = f"{self.url_project}{search_term}"
        resp_json = self._get_resp(query).json()
        # Wrap the response in a dictionary so we can re-use the parser
        resp_json = {args.pkg: resp_json}
        self._parse_api_response(resp_json)

    def query(self, args):
        """Query package information from repology.org"""
        if args.pkg_search:
            self._query_pkg_search(args)
        else:
            self._query_pkg_exact(args)

        self._report(args)


################################################################################


def main():
    """main entry point"""
    args = getargs()
    setup_logging(args.verbose)
    pkg_len_limit = 3
    if args.pkg_search and len(args.pkg_search) < pkg_len_limit:
        _LOG.fatal(
            "Package search term '%s' is shorter than %s characters. "
            "Either provide longer package search term, or specify the exact "
            "package name with '--pkg' argument. ",
            args.pkg_search,
            pkg_len_limit,
        )
        sys.exit(1)
    repology = Repology()
    repology.query(args)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
