#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Command-line interface to query CVE info from repology.org."""

import os
from argparse import ArgumentParser, ArgumentTypeError

from common.cli_args import add_verbose_argument, add_version_argument
from common.df import df_to_csv_file
from common.log import set_log_verbosity
from repology.adapter import RepologyAdapter
from repology.reporting import report_cves
from repology.session import REPOLOGY_REQUEST_TIMEOUT

###############################################################################


def _pkg_str(str_obj):
    if isinstance(str_obj, str) and len(str_obj) > 0:
        return str_obj
    raise ArgumentTypeError("Value must be a non-empty string")


def getargs(args=None):
    """Parse command line arguments."""
    desc = (
        "Query repology.org for CVEs that impact package PKG_NAME version PKG_VERSION."
    )
    epil = f"Example: ./{os.path.basename(__file__)} openssl 3.1.0"
    parser = ArgumentParser(description=desc, epilog=epil)
    helps = "Target package name"
    parser.add_argument("PKG_NAME", help=helps, type=_pkg_str)
    helps = "Target package version"
    parser.add_argument("PKG_VERSION", help=helps, type=str)
    add_verbose_argument(parser, max_level=2)
    helps = "Path to output file (default: ./repology_cves.csv)"
    parser.add_argument(
        "-o", "--out", nargs="?", help=helps, default="repology_cves.csv"
    )
    add_version_argument(parser)
    return parser.parse_args(args)


################################################################################


def query_cve(
    pkg_name, pkg_version, session=None, request_timeout=REPOLOGY_REQUEST_TIMEOUT
):
    """
    Return vulnerabilities known to repology that impact the given package name
    and version. Results are returned in pandas dataframe.
    """
    adapter = RepologyAdapter(session=session, request_timeout=request_timeout)
    return adapter.query_cves(pkg_name, pkg_version)


################################################################################


def main():
    """main entry point."""
    args = getargs()
    set_log_verbosity(args.verbose)
    df = query_cve(args.PKG_NAME, args.PKG_VERSION)
    if not report_cves(df):
        return
    df_to_csv_file(df, args.out)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
