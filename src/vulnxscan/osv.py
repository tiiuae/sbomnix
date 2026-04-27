#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Demonstrate querying OSV db for vulnerabilities based on cdx SBOM"""

import argparse
import os
import pathlib

from common.cli_args import add_verbose_argument, add_version_argument
from common.df import df_to_csv_file
from common.errors import InvalidSbomError, SbomnixError
from common.log import LOG, set_log_verbosity
from vulnxscan.osv_client import OSV

###############################################################################


def getargs(args=None):
    """Parse command line arguments"""
    desc = "Scan CycloneDX SBOM components for OSV vulnerabilities"
    epil = f"Example: ./{os.path.basename(__file__)} /path/to/sbom.json"
    parser = argparse.ArgumentParser(description=desc, epilog=epil)
    add_verbose_argument(parser)
    helps = "Path to CycloneDX SBOM json file"
    parser.add_argument("SBOM", help=helps, type=pathlib.Path)
    helps = "Path to output file (default: ./osv.csv)"
    parser.add_argument("-o", "--out", nargs="?", help=helps, default="osv.csv")
    helps = (
        'List of ecosystems to query (default: "GIT,OSS-Fuzz"). '
        "For more details, see https://osv.dev"
    )
    parser.add_argument("--ecosystems", type=str, help=helps, default="GIT,OSS-Fuzz")
    add_version_argument(parser)
    return parser.parse_args(args)


def _run(args):
    if not args.SBOM.exists():
        raise InvalidSbomError(args.SBOM)
    osv = OSV()
    ecosystems = [str(x).strip() for x in args.ecosystems.split(",")]
    osv.query_vulns(args.SBOM.as_posix(), ecosystems)
    df_vulns = osv.to_dataframe()
    df_to_csv_file(df_vulns, args.out)


def main():
    """main entry point"""
    args = getargs()
    set_log_verbosity(args.verbose)
    try:
        _run(args)
    except SbomnixError as error:
        LOG.fatal("%s", error)
        raise SystemExit(1) from error


################################################################################

if __name__ == "__main__":
    main()

################################################################################
