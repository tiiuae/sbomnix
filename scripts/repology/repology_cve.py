#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name abstract-method too-many-locals

""" Command-line interface to query CVE info from repology.org """

import logging
import os
import sys
import re
import urllib.parse
from argparse import ArgumentParser, ArgumentTypeError
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
    parse_version,
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
        "Query repology.org for CVEs that impact package PKG_NAME version "
        "PKG_VERSION."
    )
    epil = f"Example: ./{os.path.basename(__file__)} openssl 3.1.0"
    parser = ArgumentParser(description=desc, epilog=epil)
    helps = "Target package name"
    parser.add_argument("PKG_NAME", help=helps, type=_pkg_str)
    helps = "Target package version"
    parser.add_argument("PKG_VERSION", help=helps, type=str)
    helps = "Set the debug verbosity level between 0-2 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)
    helps = "Path to output file (default: ./repology_cves.csv)"
    parser.add_argument("--out", nargs="?", help=helps, default="repology_cves.csv")
    return parser.parse_args()


################################################################################


class CachedLimiterSession(CacheMixin, LimiterMixin, Session):
    """Session class with caching and rate-limiting"""

    # See: https://requests-cache.readthedocs.io/en/stable/user_guide/compatibility.html


def _parse_cve_resp(resp, pkg_name, pkg_version):
    soup = BeautifulSoup(resp.text, "html.parser")
    tables = soup.find_all("table")
    if not tables:
        _LOG.debug("Unexpected response: CVE table missing")
        return pd.DataFrame()
    cve_table = tables[0]
    headers = {}
    for idx, header in enumerate(cve_table.thead.find_all("th")):
        headers[header.text] = idx
    if not headers or "CVE ID" not in headers:
        _LOG.fatal("Unexpected response")
        sys.exit(1)
    _LOG.log(LOG_SPAM, headers)
    cve_table_rows = cve_table.tbody.find_all("tr")
    cve_dict = {}
    for row in cve_table_rows:
        affected_versions = row.find_all("span", {"class": "version version-outdated"})
        if not affected_versions:
            continue
        cols = row.find_all("td")
        if not cols:
            continue
        cve_row = cols[headers["CVE ID"]]
        _LOG.log(LOG_SPAM, "CVE: %s", cve_row)
        ver_row = cols[headers["Affected version(s)"]]
        _LOG.log(LOG_SPAM, "Versions: %s", ver_row)
        # Repology might show that a package is affected, even thought the
        # "Affected version(s)" indicates it isn't. Below, we try to manually
        # check if pkg_version is included in the affected versions.
        if not _is_affected(pkg_version, ver_row.text):
            continue
        cve_info = cve_row.text.strip().split("\n")
        _LOG.debug("CVE info: %s", cve_info)
        cve_dict.setdefault("package", []).append(pkg_name)
        cve_dict.setdefault("version", []).append(pkg_version)
        cve_dict.setdefault("cve", []).append(cve_info[0])
    df = pd.DataFrame.from_dict(cve_dict)
    df.replace(np.nan, "", regex=True, inplace=True)
    df.drop_duplicates(keep="first", inplace=True)
    return df


def _is_affected(version, affected_ver_str):
    """
    Return True if version number is included in the repology affected version
    string. Also returns true if parsing affected version string fails,
    in order to avoid false negatives.
    """
    _LOG.log(LOG_SPAM, "Affected version(s): %s", affected_ver_str)
    re_ver = re.compile(
        r"^(?P<beg>[(\[])(?P<begver>[^,]*), *(?P<endver>[^)\]]*)(?P<end>[\])])"
    )
    match = re_ver.match(affected_ver_str)
    if not match:
        _LOG.debug("Unable to parse affected version string: '%s'", affected_ver_str)
        return True
    version_parsed = parse_version(version)
    if not version_parsed:
        _LOG.fatal("Unexpected local version string: %s", version)
        sys.exit(1)
    beg_ind = match.group("beg")
    beg_ver_parsed = parse_version(match.group("begver"))
    if not beg_ver_parsed:
        return True
    end_ind = match.group("end")
    end_ver_parsed = parse_version(match.group("endver"))
    if not end_ver_parsed:
        return True
    beg_affected = False
    end_affected = False
    if (version_parsed > beg_ver_parsed) or (
        version_parsed == beg_ver_parsed and beg_ind == "["
    ):
        beg_affected = True
    if (version_parsed < end_ver_parsed) or (
        version_parsed == end_ver_parsed and end_ind == "]"
    ):
        end_affected = True
    if beg_affected and end_affected:
        return True
    return False


def _report(df):
    if df.empty:
        _LOG.warning("No matching vulnerabilities found")
        sys.exit(0)
    # Write the console report
    table = tabulate(
        df,
        headers="keys",
        tablefmt="orgtbl",
        numalign="center",
        showindex=False,
    )
    _LOG.info("Repology affected CVE(s)\n\n%s\n\n", table)


def _query_cve(pkg_name, pkg_version):
    session = CachedLimiterSession(per_second=1, expire_after=3600)
    ua_product = "repology_cli/0"
    ua_comment = "(https://github.com/tiiuae/sbomnix/tree/main/scripts/repology)"
    headers = {"User-Agent": f"{ua_product} {ua_comment}"}
    pkg = urllib.parse.quote(pkg_name)
    ver = urllib.parse.quote(pkg_version)
    query = f"https://repology.org/project/{pkg}/cves?version={ver}"
    _LOG.info("GET: %s", query)
    resp = session.get(query, headers=headers)
    _LOG.debug("resp.status_code: %s", resp.status_code)
    if resp.status_code == 404:
        _LOG.fatal("Package '%s' not found", pkg_name)
        sys.exit(1)
    resp.raise_for_status()
    return _parse_cve_resp(resp, pkg_name, pkg_version)


################################################################################


def main():
    """main entry point"""
    args = getargs()
    setup_logging(args.verbose)
    df = _query_cve(args.PKG_NAME, args.PKG_VERSION)
    _report(df)
    df_to_csv_file(df, args.out)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
