#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-locals

""" Command-line interface to query CVE info from repology.org """

import os
import sys
import re
import urllib.parse
from argparse import ArgumentParser, ArgumentTypeError
from bs4 import BeautifulSoup
import numpy as np
import pandas as pd
from tabulate import tabulate
import repology.exceptions
from common.utils import (
    LOG,
    LOG_SPAM,
    set_log_verbosity,
    df_to_csv_file,
    parse_version,
    CachedLimiterSession,
)

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


def _parse_cve_resp(resp, pkg_name, pkg_version):
    soup = BeautifulSoup(resp.text, "html.parser")
    tables = soup.find_all("table")
    if not tables:
        LOG.debug("Unexpected response: CVE table missing")
        return pd.DataFrame()
    cve_table = tables[0]
    headers = {}
    for idx, header in enumerate(cve_table.thead.find_all("th")):
        headers[header.text] = idx
    if not headers or "CVE ID" not in headers:
        LOG.fatal("Unexpected response")
        raise repology.exceptions.RepologyUnexpectedResponse
    LOG.log(LOG_SPAM, headers)
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
        LOG.log(LOG_SPAM, "CVE: %s", cve_row)
        ver_row = cols[headers["Affected version(s)"]]
        LOG.log(LOG_SPAM, "Versions: %s", ver_row)
        # Repology might show that a package is affected, even thought the
        # "Affected version(s)" indicates it isn't. Below, we try to manually
        # check if pkg_version is included in the affected versions.
        if not _is_affected(pkg_version, ver_row.text):
            continue
        cve_info = cve_row.text.strip().split("\n")
        LOG.debug("CVE info: %s", cve_info)
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
    LOG.log(LOG_SPAM, "Affected version(s): %s", affected_ver_str)
    version_local = parse_version(version)
    if not version_local:
        LOG.fatal("Unexpected local version string: %s", version)
        raise repology.exceptions.RepologyError
    # Pad with spaces to simplify regexps
    affected_ver_str = f" {affected_ver_str} "
    # Match version group
    ver_group = re.compile(
        r"(?P<beg>[(\[])(?P<begver>[^,]*), *(?P<endver>[^)\]]*)(?P<end>[\])])"
    )
    matches = re.findall(ver_group, affected_ver_str)
    if matches:
        LOG.log(LOG_SPAM, "Parsed group version(s): %s", matches)
    for impacted_group in matches:
        if len(impacted_group) != 4:
            LOG.fatal("Unexpected version group: %s", affected_ver_str)
            raise repology.exceptions.RepologyUnexpectedResponse
        # impacted_group[0] = beg
        beg_ind = impacted_group[0]
        # impacted_group[1] = begver
        beg_ver_parsed = parse_version(impacted_group[1])
        if not beg_ver_parsed:
            return True
        # impacted_group[3] = end
        end_ind = impacted_group[3]
        # impacted_group[2] = endver
        end_ver_parsed = parse_version(impacted_group[2])
        if not end_ver_parsed:
            return True
        beg_affected = False
        end_affected = False
        if (version_local > beg_ver_parsed) or (
            version_local == beg_ver_parsed and beg_ind == "["
        ):
            beg_affected = True
        if (version_local < end_ver_parsed) or (
            version_local == end_ver_parsed and end_ind == "]"
        ):
            end_affected = True
        if beg_affected and end_affected:
            return True
    # Match single version numbers
    ver_one = r"(?<= )(?<!\()(?P<version>\d[^ $)]+)(?= )"
    matches = re.findall(ver_one, affected_ver_str)
    LOG.log(LOG_SPAM, "Parsed single version(s): %s", matches)
    for impacted_version in matches:
        impacted_version = parse_version(impacted_version)
        if impacted_version == version_local:
            return True
    return False


def _report(df):
    if df is None or df.empty:
        LOG.warning("No matching vulnerabilities found")
        sys.exit(0)
    # Write the console report
    table = tabulate(
        df,
        headers="keys",
        tablefmt="orgtbl",
        numalign="center",
        showindex=False,
    )
    LOG.info("Repology affected CVE(s)\n\n%s\n\n", table)


def query_cve(pkg_name, pkg_version):
    """
    Return vulnerabilities known to repology that impact the given package name
    and version. Results are returned in pandas dataframe.
    """
    # Cache all responses locally for 6 hours
    session = CachedLimiterSession(per_second=1, expire_after=6 * 60 * 60)
    ua_product = "repology_cli/0"
    ua_comment = "(https://github.com/tiiuae/sbomnix/)"
    headers = {"User-Agent": f"{ua_product} {ua_comment}"}
    pkg = urllib.parse.quote(pkg_name)
    ver = urllib.parse.quote(pkg_version)
    query = f"https://repology.org/project/{pkg}/cves?version={ver}"
    LOG.debug("GET: %s", query)
    resp = session.get(query, headers=headers)
    LOG.debug("resp.status_code: %s", resp.status_code)
    if resp.status_code == 404:
        LOG.warning("Repology package '%s' not found", pkg_name)
        return None
    resp.raise_for_status()
    return _parse_cve_resp(resp, pkg_name, pkg_version)


################################################################################


def main():
    """main entry point"""
    args = getargs()
    set_log_verbosity(args.verbose)
    df = query_cve(args.PKG_NAME, args.PKG_VERSION)
    _report(df)
    df_to_csv_file(df, args.out)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
