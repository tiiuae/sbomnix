#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Command-line interface to query repology.org for package information."""

import os
import pathlib
from argparse import SUPPRESS, ArgumentParser, ArgumentTypeError

import repology.exceptions
from common.cli_args import add_verbose_argument, add_version_argument
from common.log import LOG, set_log_verbosity
from repology.adapter import RepologyAdapter, RepologyQuery
from repology.reporting import write_query_report

###############################################################################


def _pkg_str(str_obj):
    if isinstance(str_obj, str) and len(str_obj) > 0:
        return str_obj
    raise ArgumentTypeError("Value must be a non-empty string")


def getargs(args=None):
    """
    Parse arguments: by default parses the sys.argv if `args` is not
    specified, otherwise, parses arguments from the `args` list of strings.

    This is simply a wrapper for function ArgumentParser.parse_args(),
    returning argument attributes in argparse.Namespace object.
    """
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
    helps = "Filter reported results based on package name"
    filtergr.add_argument("-p", "--re_package", help=helps, type=str, default=None)
    helps = "Filter reported results based on version string"
    filtergr.add_argument("-V", "--re_version", help=helps, type=str, default=None)
    helps = "Filter reported results based on status string"
    filtergr.add_argument("-s", "--re_status", help=helps, type=str, default=None)
    helps = "Filter reported results based on vulnerability status"
    filtergr.add_argument("-c", "--re_vuln", help=helps, type=str, default=None)
    helps = "Summarize output result statistics"
    optional.add_argument("--stats", help=helps, action="store_true")
    add_verbose_argument(optional, root_parser=parser)
    helps = "Path to output report file (default: ./repology_report.csv)"
    optional.add_argument("-o", "--out", help=helps, default="repology_report.csv")
    add_version_argument(optional)
    if args:
        return parser.parse_args(args)
    return parser.parse_args()


################################################################################


def _query_from_args(args):
    return RepologyQuery(
        repository=args.repository,
        pkg_exact=args.pkg_exact,
        pkg_search=args.pkg_search,
        sbom_cdx=args.sbom_cdx,
        re_package=args.re_package,
        re_version=args.re_version,
        re_status=args.re_status,
        re_vuln=args.re_vuln,
    )


class Repology:
    """Compatibility wrapper that keeps CLI reporting separate from queries."""

    def __init__(self, adapter=None):
        self.adapter = RepologyAdapter() if adapter is None else adapter
        self.df = None
        self.urlq = None
        self.df_sbom = None

    def query(self, args, stdout_report=True, file_report=True):
        """Query package information from repology.org."""
        if not file_report:
            args.out = None
        self.df = self.adapter.query(_query_from_args(args))
        self.urlq = self.adapter.urlq
        self.df_sbom = self.adapter.df_sbom
        if stdout_report or args.out is not None:
            write_query_report(
                self.df,
                args,
                query_url=self.urlq,
                df_sbom=self.df_sbom,
                console_report=stdout_report,
            )
        return self.df.copy(deep=True)


################################################################################


def main():
    """main entry point"""
    args = getargs()
    set_log_verbosity(args.verbose)
    repology_cli = Repology()
    try:
        repology_cli.query(args)
    except repology.exceptions.RepologyNoMatchingPackages:
        LOG.warning("No matching packages found")


################################################################################

if __name__ == "__main__":
    main()

################################################################################
