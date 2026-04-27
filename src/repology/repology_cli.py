#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-few-public-methods,too-many-locals

"""Command-line interface to query repology.org for package information."""

import os
import pathlib
from argparse import SUPPRESS, ArgumentParser, ArgumentTypeError

import pandas as pd
from tabulate import tabulate

import repology.exceptions
from common.utils import LOG, df_to_csv_file, set_log_verbosity
from repology.adapter import RepologyAdapter, RepologyQuery

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
    filtergr.add_argument("-v", "--re_version", help=helps, type=str, default=None)
    helps = "Filter reported results based on status string"
    filtergr.add_argument("-s", "--re_status", help=helps, type=str, default=None)
    helps = "Filter reported results based on vulnerability status"
    filtergr.add_argument("-c", "--re_vuln", help=helps, type=str, default=None)
    helps = "Summarize output result statistics"
    optional.add_argument("--stats", help=helps, action="store_true")
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    optional.add_argument("--verbose", help=helps, type=int, default=1)
    helps = "Path to output report file (default: ./repology_report.csv)"
    optional.add_argument("--out", help=helps, default="repology_report.csv")
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


def _stats_sbom(df):
    df = df.copy()
    df = df.drop_duplicates(keep="first", subset=["package", "version"])
    repo_rows_n = df.shape[0]
    repo_skipped_cols = ["NO_VERSION", "IGNORED", "NOT_FOUND"]
    df_skipped = df[df.status.isin(repo_skipped_cols)]
    repo_skipped_n = df_skipped.shape[0]
    repo_skipped_pct = f"{repo_skipped_n / repo_rows_n:.0%}"
    df_ignored = df[df.status.isin(["IGNORED"])]
    ignored_n = df_ignored.shape[0]
    df_no_version = df[df.status.isin(["NO_VERSION"])]
    no_version_n = df_no_version.shape[0]
    df_not_found = df[df.status.isin(["NOT_FOUND"])]
    not_found_n = df_not_found.shape[0]
    df_repology = df[~df.status.isin(repo_skipped_cols)]
    repology_rows_n = df_repology.shape[0]
    sbom_in_repo = f"{repology_rows_n / repo_rows_n:.0%}"
    sbom_rows = f"Unique packages: {repo_rows_n} ({1:.0%})"
    sbom_skipped = (
        f"sbom packages not in repology: {repo_skipped_n} ({repo_skipped_pct})"
    )
    ignored = f"IGNORED (sbom component is not a package in repology): {ignored_n}"
    no_version = (
        f"NO_VERSION (sbom component is missing the version number): {no_version_n}"
    )
    not_found = f"NOT_FOUND (sbom component was not found in repology): {not_found_n}"
    sbom_pkgs_in_repo = f"sbom packages in repology: {repology_rows_n} ({sbom_in_repo})"
    LOG.info(
        "\n\tRepology SBOM package statistics:\n"
        "\t  %s\n"
        "\t   ==> %s\n"
        "\t   ==> %s\n"
        "\t        - %s\n"
        "\t        - %s\n"
        "\t        - %s\n",
        sbom_rows,
        sbom_pkgs_in_repo,
        sbom_skipped,
        ignored,
        no_version,
        not_found,
    )


def _stats_repology(df):
    df = df.copy(deep=True)
    base_cols = ["newest", "devel", "unique", "outdated"]
    df = df[df.status.isin(base_cols)]
    df = df.drop_duplicates(keep="first", subset=["package", "version"])
    base_rows_n = df.shape[0]
    if base_rows_n <= 0:
        LOG.debug("No base packages, skipping stats")
        return
    df_newest = df[df.status.isin(["newest"])]
    newest_rows_n = df_newest.shape[0]
    newest_pct = f"{newest_rows_n / base_rows_n:.0%}"
    df_outdated = df[df.status.isin(["outdated"])]
    outdated_rows_n = df_outdated.shape[0]
    outdated_pct = f"{outdated_rows_n / base_rows_n:.0%}"
    df_dev_uniq = df[df.status.isin(["devel", "unique"])]
    dev_uniq_rows_n = df_dev_uniq.shape[0]
    dev_uniq_pct = f"{dev_uniq_rows_n / base_rows_n:.0%}"
    df_vuln = df[df.potentially_vulnerable.isin(["1"])]
    vuln_rows_n = df_vuln.shape[0]
    vuln_pct = f"{vuln_rows_n / base_rows_n:.0%}"
    base_rows = (
        f"Unique compared packages: {base_rows_n} ({1:.0%})\t(status in: {base_cols})"
    )
    new_rows = f"newest: {newest_rows_n} ({newest_pct})"
    outdated_rows = f"outdated: {outdated_rows_n} ({outdated_pct})"
    dev_uniq_rows = f"devel or unique: {dev_uniq_rows_n} ({dev_uniq_pct})"
    vuln_rows = f"potentially vulnerable: {vuln_rows_n} ({vuln_pct})"
    about = "https://repology.org/docs/about"
    LOG.info(
        "\n\tRepology package statistics:\n"
        "\t (see the status descriptions in: %s)\n"
        "\t   %s\n"
        "\t    ==> %s\n"
        "\t    ==> %s\n"
        "\t    ==> %s\n"
        "\t    ==> %s\n",
        about,
        base_rows,
        new_rows,
        outdated_rows,
        dev_uniq_rows,
        vuln_rows,
    )


def _report(df, args, query_url, df_sbom, console_report=True):
    """Generate result report to console and to csv file."""
    report_df = df.copy(deep=True)
    console_df = report_df.copy(deep=True)
    col = "newest_upstream_release"
    console_df[col] = console_df[col].str.slice(0, 26)
    console_df = console_df[~console_df.status.isin(["IGNORED", "NO_VERSION"])]
    console_df = console_df.drop_duplicates(keep="first")
    if console_report:
        table = tabulate(
            console_df,
            headers="keys",
            tablefmt="orgtbl",
            numalign="center",
            showindex=False,
        )
        LOG.info(
            "Repology package info, packages:%s\n\n%s\n\nFor more details, see: %s\n",
            console_df.shape[0],
            table,
            query_url,
        )
        if args.stats:
            _stats_repology(report_df)
            if df_sbom is not None:
                _stats_sbom(report_df)
    if args.out is not None:
        df_to_csv_file(report_df, args.out)


class Repology:
    """Compatibility wrapper that keeps CLI reporting separate from queries."""

    def __init__(self, adapter=None):
        self.adapter = RepologyAdapter() if adapter is None else adapter
        self.df = pd.DataFrame()
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
            _report(
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
