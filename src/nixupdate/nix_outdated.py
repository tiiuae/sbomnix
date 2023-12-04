#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name

""" Command-line tool to list outdated nix dependencies in priority order"""

import logging
import os
import pathlib
from tempfile import NamedTemporaryFile
from argparse import ArgumentParser
from tabulate import tabulate
from sbomnix.sbomdb import SbomDb
import repology.repology_cli
from common.utils import (
    LOG,
    LOG_SPAM,
    set_log_verbosity,
    exec_cmd,
    df_from_csv_file,
    df_log,
    df_to_csv_file,
    nix_to_repology_pkg_name,
    exit_unless_nix_artifact,
)

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = (
        "Command line tool to list outdated nix dependencies for nix out path "
        "NIXPATH. By default, the script outputs runtime dependencies of "
        "NIXPATH that appear outdated in nixpkgs 'nix_unstable' channel - the "
        "list of output packages would potentially need a PR to update the "
        "package in nixpkgs to the latest upstream release version specified "
        "in the output table column 'version_upstream'. "
        "The list of output packages is in priority "
        "order based on how many other packages depend on the potentially "
        "outdated package."
    )
    epil = f"Example: ./{os.path.basename(__file__)} '/nix/target/out/path'"
    parser = ArgumentParser(description=desc, epilog=epil)
    # Arguments that specify the target:
    helps = "Target nix out path"
    parser.add_argument("NIXPATH", help=helps, type=pathlib.Path)
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


def _generate_sbom(target_path, runtime=True, buildtime=False):
    LOG.info("Generating SBOM for target '%s'", target_path)
    sbomdb = SbomDb(target_path, runtime, buildtime, meta_path=None)
    prefix = "nixdeps_"
    suffix = ".cdx.json"
    with NamedTemporaryFile(delete=False, prefix=prefix, suffix=suffix) as f:
        sbomdb.to_cdx(f.name, printinfo=False)
        return pathlib.Path(f.name)


def _run_repology_cli(sbompath):
    LOG.info("Running repology_cli")
    repology_cli = repology.repology_cli.Repology()
    args = []
    args.append("--repository=nix_unstable")
    args.append(f"--sbom_cdx={sbompath}")
    return repology_cli.query(
        repology.repology_cli.getargs(args),
        stdout_report=False,
        file_report=False,
    )


def _run_nix_visualize(targt_path):
    LOG.info("Running nix-visualize")
    prefix = "nix-visualize_"
    suffix = ".csv"
    with NamedTemporaryFile(delete=False, prefix=prefix, suffix=suffix) as f:
        cmd = "nix-visualize " f"--output={f.name} {targt_path}"
        exec_cmd(cmd.split())
        return pathlib.Path(f.name)


def _nix_visualize_csv_to_df(csvpath):
    LOG.debug("Transforming nix-visualize csv to dataframe")
    df = df_from_csv_file(csvpath)
    # Split column 'raw_name' to columns 'package' and 'version'
    re_split = (
        # Match anything (non '-') from the start of line up to and including
        # the first '-'
        r"^[^-]+?-"
        # Followed by the package name, which is anything up to next '-'
        r"(.+?)-"
        # Followed by the version string
        r"(\d[-_.0-9pf]*g?b?(?:pre[0-9])*(?:\+git[0-9]*)?)"
        # Optionally followed by any of the following strings
        r"(?:-lib|-bin|-env|-man|-su|-dev|-doc|-info|-nc|-host|-p[0-9]+|)"
        # Followed by the end of line
        r"$"
    )
    df[["package", "version"]] = df["raw_name"].str.extract(re_split, expand=True)
    # Fix package name so it matches repology package name
    df["package"] = df.apply(lambda row: nix_to_repology_pkg_name(row.package), axis=1)
    return df


def _generate_report_df(df_nv, df_repo):
    if df_nv is None:
        df_repo["level"] = "0"
        df_repo.rename(columns={"version": "version_repology"}, inplace=True)
        return df_repo
    df = df_nv.merge(
        df_repo,
        how="left",
        left_on=["package", "version"],
        right_on=["package", "version_sbom"],
        suffixes=["", "_repology"],
    )
    LOG.log(LOG_SPAM, "Merged nix-visualize and repology data:")
    df_log(df, LOG_SPAM)
    return df


def _drop_newest_dups(df_con, df_cmp):
    # Drop outdated package from df_con if a version 'newest' is available
    # in df_cmp
    df_ret = df_con.copy(deep=True)
    for row in df_con.itertuples():
        df_pkgs = df_cmp[df_cmp["package"] == row.nix_package]
        df_newest = df_pkgs[df_pkgs["status"] == "newest"]
        if not df_newest.empty:
            LOG.debug(
                "Ignoring outdated package '%s' since newest version is also available",
                row.nix_package,
            )
            df_ret = df_ret[df_ret.nix_package != row.nix_package]
    return df_ret


def _report(df, args):
    if df is None or df.empty:
        LOG.info("No outdated dependencies found")
        return
    LOG.info("Writing console report")
    # Rename and select the following columns to the output report
    select_cols = {
        "level": "priority",
        "package": "nix_package",
        "version_sbom": "version_local",
        "version_repology": "version_nixpkgs",
        "newest_upstream_release": "version_upstream",
    }
    if args.local:
        # Select pkgs that need update locally
        col = "sbom_version_classify"
        re_val = "sbom_pkg_needs_update"
        df_console = df[df[col] == re_val]
        df_console = df_console.rename(columns=select_cols)[select_cols.values()]
        df_console.drop_duplicates(
            df_console.columns.difference(["priority"]), keep="first", inplace=True
        )
        if args.buildtime:
            df_console = df_console.drop(["priority"], axis=1)
        table = tabulate(
            df_console,
            headers="keys",
            tablefmt="orgtbl",
            numalign="center",
            showindex=False,
        )
        _console_out_table(table, args.local, args.buildtime)
    else:
        # Select pkgs that need update in nixpkgs
        col = "repo_version_classify"
        re_val = "repo_pkg_needs_update"
        df_console = df[df[col] == re_val]
        df_console = df_console.rename(columns=select_cols)[select_cols.values()]
        df_console.drop_duplicates(
            df_console.columns.difference(["priority"]), keep="first", inplace=True
        )
        df_console = _drop_newest_dups(df_console, df)
        if args.buildtime:
            df_console = df_console.drop(["priority"], axis=1)
        table = tabulate(
            df_console,
            headers="keys",
            tablefmt="orgtbl",
            numalign="center",
            showindex=False,
        )
        _console_out_table(table, args.local, args.buildtime)

    if LOG.level <= logging.DEBUG:
        # Write the full merged df for debugging
        df_to_csv_file(df, "df_nixoutdated_merged.csv")

    # File report
    df_to_csv_file(df_console, args.out)


def _console_out_table(table, local=False, buildtime=False):
    update_target = "in nixpkgs"
    if local:
        update_target = "locally"
    priority = ":"
    if not buildtime:
        priority = (
            " (in priority order based on how many other "
            "packages depend on the potentially outdated package):"
        )
    LOG.info(
        "Dependencies that need update %s%s\n\n%s\n\n",
        update_target,
        priority,
        table,
    )


################################################################################


def main():
    """main entry point"""
    args = getargs()
    set_log_verbosity(args.verbose)
    target_path_abs = args.NIXPATH.resolve().as_posix()
    runtime = args.buildtime is False
    dtype = "runtime" if runtime else "buildtime"
    LOG.info("Checking %s dependencies referenced by '%s'", dtype, target_path_abs)
    exit_unless_nix_artifact(target_path_abs, force_realise=runtime)

    sbom_path = _generate_sbom(target_path_abs, runtime, args.buildtime)
    LOG.debug("Using SBOM '%s'", sbom_path)

    df_repology = _run_repology_cli(sbom_path)
    if LOG.level > logging.DEBUG:
        sbom_path.unlink(missing_ok=True)
    df_log(df_repology, LOG_SPAM)

    if not args.buildtime:
        nix_visualize_out = _run_nix_visualize(target_path_abs)
        LOG.debug("Using nix-visualize out: '%s'", nix_visualize_out)
        df_nix_visualize = _nix_visualize_csv_to_df(nix_visualize_out)
        df_log(df_nix_visualize, LOG_SPAM)
        if LOG.level > logging.DEBUG:
            # Remove temp file unless verbosity is DEBUG or more verbose
            nix_visualize_out.unlink(missing_ok=True)
    else:
        LOG.info("Not running nix-visualize due to '--buildtime' argument")
        df_nix_visualize = None

    df_report = _generate_report_df(df_nix_visualize, df_repology)
    _report(df_report, args)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
