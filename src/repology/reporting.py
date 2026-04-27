# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-arguments,too-many-locals

"""Console and CSV reporting helpers for Repology commands."""

from tabulate import tabulate

from common.df import df_to_csv_file
from common.log import LOG


def _stats_sbom(df, *, log=LOG):
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
    log.info(
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


def _stats_repology(df, *, log=LOG):
    df = df.copy(deep=True)
    base_cols = ["newest", "devel", "unique", "outdated"]
    df = df[df.status.isin(base_cols)]
    df = df.drop_duplicates(keep="first", subset=["package", "version"])
    base_rows_n = df.shape[0]
    if base_rows_n <= 0:
        log.debug("No base packages, skipping stats")
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
    log.info(
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


def report_cves(df, *, log=LOG):
    """Render a CVE table to the console when rows exist."""
    if df is None or df.empty:
        log.warning("No matching vulnerabilities found")
        return False
    table = tabulate(
        df,
        headers="keys",
        tablefmt="orgtbl",
        numalign="center",
        showindex=False,
    )
    log.info("Repology affected CVE(s)\n\n%s\n\n", table)
    return True


def write_query_report(df, args, *, query_url, df_sbom, console_report=True, log=LOG):
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
        log.info(
            "Repology package info, packages:%s\n\n%s\n\nFor more details, see: %s\n",
            console_df.shape[0],
            table,
            query_url,
        )
        if args.stats:
            _stats_repology(report_df, log=log)
            if df_sbom is not None:
                _stats_sbom(report_df, log=log)
    if args.out is not None:
        df_to_csv_file(report_df, args.out)
