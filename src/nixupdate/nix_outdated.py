#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Command-line tool to list outdated nix dependencies in priority order"""

import os
from argparse import ArgumentParser
from tempfile import NamedTemporaryFile

from common.errors import SbomnixError
from common.log import LOG, set_log_verbosity
from common.proc import exec_cmd
from nixupdate.nix_visualize import (
    nix_visualize_csv_to_df as _nix_visualize_csv_to_df_impl,
)
from nixupdate.nix_visualize import run_nix_visualize as _run_nix_visualize_impl
from nixupdate.pipeline import OutdatedScanHooks, collect_outdated_scan_data
from nixupdate.pipeline import query_repology as _query_repology_impl
from nixupdate.report import console_out_table as _console_out_table_impl
from nixupdate.report import drop_newest_duplicates as _drop_newest_dups_impl
from nixupdate.report import generate_report_df as _generate_report_df_impl
from nixupdate.report import write_report as _write_report_impl
from sbomnix.cli_utils import generate_temp_sbom, resolve_nix_target

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = (
        "Command line tool to list outdated nix dependencies for NIXREF. "
        "By default, the script outputs runtime dependencies of "
        "NIXREF that appear outdated in nixpkgs 'nix_unstable' channel - the "
        "list of output packages would potentially need a PR to update the "
        "package in nixpkgs to the latest upstream release version specified "
        "in the output table column 'version_upstream'. "
        "The list of output packages is in priority "
        "order based on how many other packages depend on the potentially "
        "outdated package."
    )
    epil = f"Example: ./{os.path.basename(__file__)} '/nix/path/or/flakeref'"
    parser = ArgumentParser(description=desc, epilog=epil)
    # Arguments that specify the target:
    helps = (
        "Target nix store path (e.g. derivation file or nix output path) or flakeref"
    )
    parser.add_argument("NIXREF", help=helps, type=str)
    # Other arguments:
    helps = (
        "Include locally outdated dependencies to the output. "
        "By default, the script "
        "outputs dependencies outdated in nixpkgs. With this option "
        "the tool also includes to the output the dependencies that are "
        "outdated locally (i.e. would need nix flake update or similar). "
        "The output list includes runtime dependencies that are locally "
        "outdated and would have an update available in nixpkgs nix_unstable "
        "channel, as well as runtime "
        "dependencies that are outdated in nixpkgs nix_unstable channel "
        "that would have an update in the package's upstream repository."
    )
    parser.add_argument("--local", help=helps, action="store_true")
    helps = "Scan target buildtime instead of runtime dependencies."
    parser.add_argument("--buildtime", help=helps, action="store_true")
    helps = "Path to output file (default: ./nix_outdated.csv)"
    parser.add_argument("--out", nargs="?", help=helps, default="nix_outdated.csv")
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)
    return parser.parse_args()


################################################################################


def _query_repology(sbompath):
    return _query_repology_impl(sbompath)


def _run_nix_visualize(target_path):
    return _run_nix_visualize_impl(
        target_path,
        exec_cmd_fn=exec_cmd,
        tempfile_factory=NamedTemporaryFile,
        log=LOG,
    )


def _nix_visualize_csv_to_df(csvpath):
    LOG.debug("Transforming nix-visualize csv to dataframe")
    return _nix_visualize_csv_to_df_impl(csvpath)


def _generate_report_df(df_nv, df_repo):
    return _generate_report_df_impl(df_nv, df_repo, log=LOG)


def _drop_newest_dups(df_con, df_cmp):
    return _drop_newest_dups_impl(df_con, df_cmp, log=LOG)


def _report(df, args):
    _write_report_impl(df, args, log=LOG)


def _console_out_table(table, local=False, buildtime=False):
    _console_out_table_impl(table, local=local, buildtime=buildtime, log=LOG)


################################################################################


def main():
    """main entry point"""
    args = getargs()
    set_log_verbosity(args.verbose)
    try:
        _run(args)
    except SbomnixError as error:
        LOG.fatal("%s", error)
        raise SystemExit(1) from error


def _run(args):
    target = resolve_nix_target(args.NIXREF, buildtime=args.buildtime)
    scan_data = collect_outdated_scan_data(
        target.path,
        args.buildtime,
        hooks=OutdatedScanHooks(
            query_repology=_query_repology,
            generate_temp_sbom=generate_temp_sbom,
            run_nix_visualize=_run_nix_visualize,
            parse_nix_visualize=_nix_visualize_csv_to_df,
        ),
    )
    df_report = _generate_report_df(scan_data.nix_visualize, scan_data.repology)
    _report(df_report, args)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
