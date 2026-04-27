# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Report shaping helpers for ``nix_outdated``."""

import logging

from tabulate import tabulate

from common.df import df_log, df_to_csv_file
from common.log import LOG, LOG_SPAM


def generate_report_df(df_nix_visualize, df_repology, *, log=LOG, log_spam=LOG_SPAM):
    """Merge Repology and ``nix-visualize`` data into a reporting dataframe."""
    if df_nix_visualize is None:
        df_repology = df_repology.copy(deep=True)
        df_repology["level"] = "0"
        df_repology.rename(columns={"version": "version_repology"}, inplace=True)
        return df_repology
    df = df_nix_visualize.merge(
        df_repology,
        how="left",
        left_on=["package", "version"],
        right_on=["package", "version_sbom"],
        suffixes=["", "_repology"],
    )
    log.log(log_spam, "Merged nix-visualize and repology data:")
    df_log(df, log_spam)
    return df


def drop_newest_duplicates(df_console, df_compare, *, log=LOG):
    """Drop outdated rows when a corresponding ``newest`` row also exists."""
    df_ret = df_console.copy(deep=True)
    for row in df_console.itertuples():
        df_pkgs = df_compare[df_compare["package"] == row.nix_package]
        df_newest = df_pkgs[df_pkgs["status"] == "newest"]
        if not df_newest.empty:
            log.debug(
                "Ignoring outdated package '%s' since newest version is also available",
                row.nix_package,
            )
            df_ret = df_ret[df_ret.nix_package != row.nix_package]
    return df_ret


def console_out_table(table, *, local=False, buildtime=False, log=LOG):
    """Write the formatted console table."""
    update_target = "in nixpkgs"
    if local:
        update_target = "locally"
    priority = ":"
    if not buildtime:
        priority = (
            " (in priority order based on how many other "
            "packages depend on the potentially outdated package):"
        )
    log.info(
        "Dependencies that need update %s%s\n\n%s\n\n",
        update_target,
        priority,
        table,
    )


def write_report(df, args, *, log=LOG):
    """Write the nix-outdated console and CSV reports."""
    if df is None or df.empty:
        log.info("No outdated dependencies found")
        return
    log.info("Writing console report")
    select_cols = {
        "level": "priority",
        "package": "nix_package",
        "version_sbom": "version_local",
        "version_repology": "version_nixpkgs",
        "newest_upstream_release": "version_upstream",
    }
    if args.local:
        df_console = df[df["sbom_version_classify"] == "sbom_pkg_needs_update"]
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
        console_out_table(table, local=args.local, buildtime=args.buildtime, log=log)
    else:
        df_console = df[df["repo_version_classify"] == "repo_pkg_needs_update"]
        df_console = df_console.rename(columns=select_cols)[select_cols.values()]
        df_console.drop_duplicates(
            df_console.columns.difference(["priority"]), keep="first", inplace=True
        )
        df_console = drop_newest_duplicates(df_console, df, log=log)
        if args.buildtime:
            df_console = df_console.drop(["priority"], axis=1)
        table = tabulate(
            df_console,
            headers="keys",
            tablefmt="orgtbl",
            numalign="center",
            showindex=False,
        )
        console_out_table(table, local=args.local, buildtime=args.buildtime, log=log)

    if log.level <= logging.DEBUG:
        df_to_csv_file(df, "df_nixoutdated_merged.csv")
    df_to_csv_file(df_console, args.out)
