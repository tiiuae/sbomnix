#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name too-many-return-statements fixme abstract-method

"""
Command line tool to demonstrate finding and classifying potential security
updates for dependencies of given nix target
"""

import os
import sys
import pathlib
import json
import urllib.parse
from tempfile import NamedTemporaryFile
from argparse import ArgumentParser
from requests import Session
from requests_cache import CacheMixin
from requests_ratelimiter import LimiterMixin
import pandas as pd
from tabulate import tabulate
from sbomnix.utils import (
    LOG,
    LOG_SPAM,
    set_log_verbosity,
    exec_cmd,
    df_from_csv_file,
    df_log,
    df_to_csv_file,
    nix_to_repology_pkg_name,
    parse_version,
    version_distance,
    exit_unless_nix_artifact,
)

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = (
        "Command line tool to demonstrate finding and classifying potential "
        "security updates for nix target or any of its dependencies."
    )
    epil = f"Example: ./{os.path.basename(__file__)} '/nix/target/out/path'"
    parser = ArgumentParser(description=desc, epilog=epil)
    # Arguments that specify the target:
    helps = "Target nix out path"
    parser.add_argument("NIXPATH", help=helps, type=pathlib.Path)
    # Other arguments:
    helps = (
        "Search nixpkgs github for PRs that might include more information "
        "concerning the fix for the vulnerability. "
        "This option adds a URL to best matching PR (if any) "
        "to the output table. The PR search takes significant "
        "time due to github API rate limits, which is why this feature is "
        "not enabled by default."
    )
    parser.add_argument("--pr", help=helps, action="store_true")
    helps = (
        "Include target's buildtime dependencies to the scan. "
        "By default, only runtime dependencies are considered."
    )
    parser.add_argument("--buildtime", help=helps, action="store_true")
    helps = "Path to output file (default: ./nix_secupdates.csv)"
    parser.add_argument("--out", nargs="?", help=helps, default="nix_secupdates.csv")
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)
    return parser.parse_args()


class CachedLimiterSession(CacheMixin, LimiterMixin, Session):
    """Session class with caching and rate-limiting"""


_repology_cve_dfs = {}
_repology_cli_dfs = {}
_repology_nix_repo = "nix_unstable"
# Rate-limited and cached session. For github api rate limits, see:
# https://docs.github.com/en/rest/search?apiVersion=latest#rate-limit
_session = CachedLimiterSession(per_minute=9, per_second=1, expire_after=3600)


def _run_vulnxscan(target_path, buildtime=False):
    LOG.info("Running vulnxscan for target '%s'", target_path)
    prefix = "secupdates_vulnxscan_"
    suffix = ".csv"
    with NamedTemporaryFile(delete=False, prefix=prefix, suffix=suffix) as f:
        extra_args = "--buildtime" if buildtime else ""
        cmd = f"vulnxscan.py {extra_args} --out={f.name} {target_path}"
        exec_cmd(cmd.split())
        try:
            df = df_from_csv_file(f.name)
            LOG.info("Using vulnxscan result: '%s'", f.name)
        except pd.errors.EmptyDataError:
            LOG.info("No vulnerabilities found")
            sys.exit(0)
        return df


def _select_newest(df):
    df_ret = None
    for pkg_name in df["package"].unique():
        df_pkg = df[df["package"] == str(pkg_name)]
        # Newest by status:
        df_newest = df_pkg[df_pkg["status"] == "newest"]
        if df_newest.empty:
            # If there's no newest by status, take the newest by version:
            df_newest = df_pkg.sort_values(by=["version"]).iloc[[-1]]
        df_ret = pd.concat([df_ret, df_newest], ignore_index=True)
    return df_ret


def _run_repology_cli(pname, match_type="--pkg_exact"):
    LOG.log(LOG_SPAM, "Running repology_cli for '%s'", pname)
    df_repology_cli = None
    if pname in _repology_cli_dfs:
        LOG.log(LOG_SPAM, "Using cached repology_cli results")
        df_repology_cli = _repology_cli_dfs[pname]
    else:
        prefix = "repology_cli_"
        suffix = ".csv"
        with NamedTemporaryFile(delete=True, prefix=prefix, suffix=suffix) as f:
            repo = f"--repository {_repology_nix_repo}"
            status = "--re_status=outdated|newest|devel|unique"
            out = f"--out={f.name}"
            search = f"{match_type}={pname}"
            cmd = f"repology_cli.py {repo} {status} {search} {out} "
            ret = exec_cmd(cmd.split(), raise_on_error=False, return_error=True)
            if ret and ret.stderr and "No matching packages" in ret.stderr:
                return None
            df_repology_cli = df_from_csv_file(f.name)
            df_repology_cli = _select_newest(df_repology_cli)
            _repology_cli_dfs[pname] = df_repology_cli
            df_log(df_repology_cli, LOG_SPAM)
    return df_repology_cli


def _add_vuln_item(out_dict, vuln, df_repo=None):
    if df_repo is None:
        out_dict.setdefault("vuln_id", []).append(vuln.vuln_id)
        out_dict.setdefault("url", []).append(vuln.url)
        out_dict.setdefault("package", []).append(vuln.package)
        out_dict.setdefault("version_local", []).append(vuln.version)
        out_dict.setdefault("version_nixpkgs", []).append("")
        out_dict.setdefault("version_upstream", []).append("")
        out_dict.setdefault("package_repology", []).append("")
        out_dict.setdefault("sortcol", []).append(vuln.sortcol)
        return
    for item in df_repo.itertuples():
        out_dict.setdefault("vuln_id", []).append(vuln.vuln_id)
        out_dict.setdefault("url", []).append(vuln.url)
        out_dict.setdefault("package", []).append(vuln.package)
        out_dict.setdefault("version_local", []).append(vuln.version)
        out_dict.setdefault("version_nixpkgs", []).append(item.version)
        if item.newest_upstream_release and ";" in item.newest_upstream_release:
            version_upstream_str = item.newest_upstream_release.split(";")[0]
        else:
            version_upstream_str = item.newest_upstream_release
        out_dict.setdefault("version_upstream", []).append(version_upstream_str)
        out_dict.setdefault("package_repology", []).append(item.package)
        out_dict.setdefault("sortcol", []).append(vuln.sortcol)


def _version_similarity(row):
    ratio = version_distance(row.version, row.version_cmp)
    LOG.log(
        LOG_SPAM,
        "Version similarity ('%s' vs '%s' ==> %s)",
        row.version,
        row.version_cmp,
        ratio,
    )
    return ratio


def _query_repology_versions(df_vuln_pkgs):
    LOG.info("Querying repology")
    result_dict = {}
    for vuln in df_vuln_pkgs.itertuples():
        repo_pkg = nix_to_repology_pkg_name(vuln.package)
        LOG.log(LOG_SPAM, "Package '%s' ==> '%s'", vuln.package, repo_pkg)
        df_repology_cli = _run_repology_cli(repo_pkg)
        if df_repology_cli is not None and not df_repology_cli.empty:
            # If there's one match, there's no need to check other details
            if df_repology_cli.shape[0] == 1:
                LOG.log(LOG_SPAM, "One repology package matches")
                _add_vuln_item(result_dict, vuln, df_repology_cli)
                continue
            # Match based on version: exact match
            df = df_repology_cli[df_repology_cli["version"] == vuln.version]
            if not df.empty:
                LOG.log(LOG_SPAM, "Exact version match '%s'", vuln.version)
                _add_vuln_item(result_dict, vuln, df)
                continue
            # Match based on version: similarity
            df_repology_cli["version_cmp"] = vuln.version
            df_repology_cli["similarity"] = df_repology_cli.apply(
                _version_similarity, axis=1
            )
            df = df_repology_cli[df_repology_cli["similarity"] >= 0.7]
            if not df.empty:
                LOG.log(LOG_SPAM, "Version similarity match:\n%s", df)
                best_match = df["similarity"].max()
                df = df[df["similarity"] == best_match]
                LOG.log(LOG_SPAM, "Selecting best match based on version:\n%s", df)
                _add_vuln_item(result_dict, vuln, df)
                continue
            # Otherwise, we need to conclude that we don't know which repology
            # package (as returned by _run_repology_cli()), the nix package
            # 'vuln.package' maps to.
            # TODO: if we end up here, we could do another search with:
            # _run_repology_cli(repo_pkg, match_type='--pkg_search')
            LOG.log(LOG_SPAM, "Vague match in repology pkg, adding vuln only")
            _add_vuln_item(result_dict, vuln)
        else:
            _add_vuln_item(result_dict, vuln)
    df_result = pd.DataFrame(result_dict)
    df_result.fillna("", inplace=True)
    df_result.reset_index(drop=True, inplace=True)
    return df_result


def _find_secupdates(args):
    target_path_abs = args.NIXPATH.resolve().as_posix()
    # Find vulnerable packages
    df_vulnx = _run_vulnxscan(target_path_abs, args.buildtime)
    uids = ["vuln_id", "package", "version", "url", "sortcol"]
    df_vuln_pkgs = df_vulnx.groupby(by=uids).size().reset_index(name="count")
    LOG.debug("Number of vulnerable packages: %s", df_vuln_pkgs.shape[0])
    df_log(df_vuln_pkgs, LOG_SPAM)
    # Find the repology version info for the vulnerable packages
    df_vuln_pkgs = _query_repology_versions(df_vuln_pkgs)
    LOG.debug("Vulnerable pkgs with repology version info: %s", df_vuln_pkgs.shape[0])
    df_log(df_vuln_pkgs, LOG_SPAM)
    # Classify each vulnerable package
    df_vuln_pkgs["classify"] = df_vuln_pkgs.apply(_vuln_update_classify, axis=1)
    # Find potentially relevant PR
    if args.pr:
        LOG.info("Querying github PRs")
        df_vuln_pkgs["nixpkgs_pr"] = df_vuln_pkgs.apply(_vuln_nixpkgs_pr, axis=1)
    # Sort the data based on the following columns
    sort_cols = ["sortcol", "package", "version_local"]
    df_vuln_pkgs.sort_values(by=sort_cols, ascending=False, inplace=True)
    return df_vuln_pkgs


def _pkg_is_vulnerable(repo_pkg_name, pkg_version, cve_id=None):
    """
    Return true if given pkg version is vulnerable. If cve_id is specified,
    return true only if pkg is affected by the given cve id.
    """
    # For now, we rely on repology for the vulnerability info.
    LOG.debug("Finding vulnerability status for %s:%s", repo_pkg_name, pkg_version)
    key = f"{repo_pkg_name}:{pkg_version}"
    if key in _repology_cve_dfs:
        LOG.log(LOG_SPAM, "Using cached repology_cve results")
        df = _repology_cve_dfs[key]
    else:
        prefix = "repology_cve_"
        suffix = ".csv"
        with NamedTemporaryFile(delete=True, prefix=prefix, suffix=suffix) as f:
            args = f"{repo_pkg_name} {pkg_version}"
            cmd = f"repology_cve.py --out={f.name} {args}"
            exec_cmd(cmd.split(), raise_on_error=False)
            try:
                df = df_from_csv_file(f.name)
                df_log(df, LOG_SPAM)
            except pd.errors.EmptyDataError:
                df = pd.DataFrame()
        _repology_cve_dfs[key] = df
    if cve_id and not df.empty:
        df = df[df["cve"] == cve_id]
    return not df.empty


def _vuln_update_classify(row):
    if not row.version_nixpkgs and not row.version_upstream:
        return "err_missing_repology_version"
    # Check that the package is also vulnerable based on repology
    if row.version_local and not _pkg_is_vulnerable(
        row.package_repology, row.version_local, row.vuln_id
    ):
        return "err_not_vulnerable_based_on_repology"
    # Check if there's an update available in nixpkgs
    version_local = parse_version(row.version_local)
    version_nixpkgs = parse_version(row.version_nixpkgs)
    if not version_local:
        return "err_invalid_version"
    if not version_nixpkgs:
        return "err_invalid_version"
    if row.version_nixpkgs and version_local < version_nixpkgs:
        # Classify accordingly if the nixpkgs update is not vulnerable
        if not _pkg_is_vulnerable(
            row.package_repology, row.version_nixpkgs, row.vuln_id
        ):
            return "fix_update_to_version_nixpkgs"
    # Check if there's an update available in upstream
    version_upstream = parse_version(row.version_upstream)
    if not version_upstream:
        return "err_invalid_version"
    if row.version_upstream and version_local < version_upstream:
        # Classify accordingly if the upstream update is not vulnerable
        if not _pkg_is_vulnerable(row.package_repology, version_upstream, row.vuln_id):
            return "fix_update_to_version_upstream"
    # Issue appears valid, but there's no known fix
    return "fix_not_available"


def _search_result_append(prs, result):
    maxres = 5
    for item in prs["items"]:
        if len(result) >= maxres:
            # Log all the found PR urls, even though we include only the first
            # maxres to the main output
            LOG.log(
                LOG_SPAM, "More than %s PRs, skipping: %s", maxres, item["html_url"]
            )
            continue
        result.add(item["html_url"])
    return result


def _vuln_nixpkgs_pr(row):
    # See: https://docs.github.com/en/search-github
    nixpr = "repo:NixOS/nixpkgs is:pr"
    unmerged = "is:unmerged is:open"
    merged = "is:merged"
    ver = None
    result = set()
    # Query unmerged PRs based on vuln_id
    prs = _github_query(f"{nixpr} {unmerged} {row.vuln_id}")
    _search_result_append(prs, result)
    # Query merged PRs based vuln_id
    prs = _github_query(f"{nixpr} {merged} {row.vuln_id}")
    _search_result_append(prs, result)
    # Attempt version-based match for the following classifications:
    if row.classify == "fix_update_to_version_nixpkgs":
        ver = row.version_nixpkgs
    elif row.classify == "fix_update_to_version_upstream":
        ver = row.version_upstream
    if ver:
        pkg = row.package
        # Query unmerged PRs based on pkg name and version in title
        prs = _github_query(f"{nixpr} {unmerged} {pkg} in:title {ver} in:title")
        _search_result_append(prs, result)
        # Query merged PRs based on pkg name and version in title
        prs = _github_query(f"{nixpr} {merged} {pkg} in:title {ver} in:title")
        _search_result_append(prs, result)
    return " \n".join(sorted(list(result)))


def _report(df_vulns):
    df = df_vulns.copy()
    if df.empty:
        LOG.warning("No vulnerabilities found")
        sys.exit(0)
    # Truncate version strings
    df["version_local"] = df["version_local"].str.slice(0, 16)
    df["version_nixpkgs"] = df["version_nixpkgs"].str.slice(0, 16)
    df["version_upstream"] = df["version_upstream"].str.slice(0, 16)
    # Don't print the following columns to console
    df = df.drop("sortcol", axis=1)
    df = df.drop("package_repology", axis=1)
    # Write the console report
    table = tabulate(
        df,
        headers="keys",
        tablefmt="orgtbl",
        numalign="center",
        showindex=False,
    )
    LOG.info(
        "Console report\n\n"
        "Potential vulnerabilities impacting version_local, with suggested "
        "update actions:\n\n%s\n\n",
        table,
    )


def _github_query(query_str):
    query_str = urllib.parse.quote(query_str, safe=":/")
    query = f"https://api.github.com/search/issues?q={query_str}"
    LOG.debug("GET: %s", query)
    resp = _session.get(query)
    resp.raise_for_status()
    resp_json = json.loads(resp.text)
    LOG.log(LOG_SPAM, "total_count=%s", resp_json["total_count"])
    return resp_json


################################################################################


def main():
    """main entry point"""
    args = getargs()
    set_log_verbosity(args.verbose)
    exit_unless_nix_artifact(args.NIXPATH.resolve().as_posix())
    df = _find_secupdates(args)
    _report(df)
    df_to_csv_file(df, args.out)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
