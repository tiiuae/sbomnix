#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-return-statements

"""
Utility functions
"""


import json
import logging
import pathlib
import re
import time
import urllib.parse

from tempfile import NamedTemporaryFile
import pandas as pd

from common.utils import (
    LOG,
    LOG_SPAM,
    CachedLimiterSession,
    df_log,
    nix_to_repology_pkg_name,
    parse_version,
    version_distance,
)
import repology
from repology.repology_cli import Repology
from sbomnix.sbomdb import SbomDb


################################################################################

# Helpers


def _reformat_scanner(val):
    if val and not pd.isnull(val):
        return "1"
    return "0"


def _vuln_sortcol(row):
    # Return a string that should make the vulns we want to see high
    # on the report list to bubble up when sorted in ascending order based
    # on the returned string
    match = re.match(r".*[A-Za-z][-_]([1-2][0-9]{3})[-_]([0-9]+).*", row.vuln_id)
    if match:
        year = match.group(1)
        number = str(match.group(2)).zfill(10)
        return f"{year}A{number}"
    if row.modified and not pd.isnull(row.modified):
        return f"{row.modified.year}A{int(row.modified.timestamp())}"
    return str(row.vuln_id)


def _vuln_url(row):
    osv_url = "https://osv.dev/"
    nvd_url = "https://nvd.nist.gov/vuln/detail/"
    if "cve" in row.vuln_id.lower():
        return f"{nvd_url}{row.vuln_id}"
    if row.osv:
        return f"{osv_url}{row.vuln_id}"
    return ""


def _is_patched(row):
    if row.vuln_id and str(row.vuln_id).lower() in str(row.patches).lower():
        patches = row.patches.split()
        patch = [p for p in patches if str(row.vuln_id).lower() in str(p).lower()]
        LOG.info("%s for '%s' is patched with: %s", row.vuln_id, row.package, patch)
        return True
    return False


def _triage(df_report, search_nix_prs):
    LOG.debug("")
    df = df_report.copy()
    uids = ["vuln_id", "package", "severity", "version", "url", "sortcol"]
    if "whitelist" in df.columns:
        uids.append("whitelist")
        uids.append("whitelist_comment")
    df_vuln_pkgs = df.groupby(by=uids).size().reset_index(name="count")
    LOG.debug("Number of vulnerable packages: %s", df_vuln_pkgs.shape[0])
    if df_vuln_pkgs.empty:
        return df_vuln_pkgs
    df_log(df_vuln_pkgs, LOG_SPAM)
    # Find the repology version info for vulnerable packages
    df_vuln_pkgs = _query_repology_versions(df_vuln_pkgs)
    LOG.debug("Vulnerable pkgs with repology version info: %s", df_vuln_pkgs.shape[0])
    df_log(df_vuln_pkgs, LOG_SPAM)
    # Classify each vulnerable package
    df_vuln_pkgs["classify"] = df_vuln_pkgs.apply(_vuln_update_classify, axis=1)
    # Find potentially relevant nixpkgs PR
    if search_nix_prs:
        LOG.info("Querying nixpkgs github PRs")
        df_vuln_pkgs["nixpkgs_pr"] = df_vuln_pkgs.apply(_vuln_nixpkgs_pr, axis=1)
    # Sort the data based on the following columns
    sort_cols = ["sortcol", "package", "severity", "version_local"]
    df_vuln_pkgs.sort_values(by=sort_cols, ascending=False, inplace=True)
    return df_vuln_pkgs


def _vuln_nixpkgs_pr(row):
    if hasattr(row, "whitelist") and row.whitelist:
        # Whitelisted: skip github nixpkgs pr search
        LOG.log(LOG_SPAM, "Whitelisted, skipping PR query: %s", row)
        return ""
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


def _github_query(query_str, delay=60):
    query_str_quoted = urllib.parse.quote(query_str, safe=":/")
    query = f"https://api.github.com/search/issues?q={query_str_quoted}"
    LOG.debug("GET: %s", query)
    resp = _session.get(query)
    if not resp.ok and "rate limit exceeded" in resp.text:
        max_delay = 60
        if delay > max_delay:
            LOG.warning("Rate limit exceeded requesting %s", query)
            ret = json.loads("{}")
            ret["items"] = []
            return ret
        LOG.debug("Sleeping %s seconds before re-requesting", delay)
        time.sleep(delay)
        LOG.debug("Re-requesting")
        return _github_query(query_str, delay * 2)
    resp.raise_for_status()
    resp_json = json.loads(resp.text)
    LOG.log(LOG_SPAM, "total_count=%s", resp_json["total_count"])
    return resp_json


def _generate_sbom(target_path, buildtime=False):
    LOG.info("Generating SBOM for target '%s'", target_path)
    sbomdb = SbomDb(target_path, buildtime, include_meta=False)
    prefix = "vulnxscan_"
    cdx_suffix = ".json"
    csv_suffix = ".csv"
    with NamedTemporaryFile(
        delete=False, prefix=prefix, suffix=cdx_suffix
    ) as fcdx, NamedTemporaryFile(
        delete=False, prefix=prefix, suffix=csv_suffix
    ) as fcsv:
        sbomdb.to_cdx(fcdx.name, printinfo=False)
        sbomdb.to_csv(fcsv.name, loglevel=logging.DEBUG)
        return pathlib.Path(fcdx.name), pathlib.Path(fcsv.name)


def _is_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            json_obj = json.load(f)
            if json_obj:
                return True
            return False
    except (json.JSONDecodeError, OSError, UnicodeError):
        return False


################################################################################

# Triage


_repology_cve_dfs = {}
_repology_cli_dfs = {}
# Rate-limited and cached session. For github api rate limits, see:
# https://docs.github.com/en/rest/search?apiVersion=latest#rate-limit
# (caching all responses locally for 6 hours)
_session = CachedLimiterSession(per_minute=9, per_second=1, expire_after=6 * 60 * 60)


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
        df = repology.repology_cve.query_cve(str(repo_pkg_name), str(pkg_version))
        if df is None:
            df = pd.DataFrame()
        df_log(df, LOG_SPAM)
        _repology_cve_dfs[key] = df
    if cve_id and not df.empty:
        df = df[df["cve"] == cve_id]
    return not df.empty


def _run_repology_cli(pname, match_type="--pkg_exact"):
    LOG.log(LOG_SPAM, "Running repology_cli for '%s'", pname)
    df_repology_cli = None
    if pname in _repology_cli_dfs:
        LOG.log(LOG_SPAM, "Using cached repology_cli results")
        df_repology_cli = _repology_cli_dfs[pname]
    else:
        repology_cli = Repology()
        args = []
        args.append("--repository=nix_unstable")
        args.append("--re_status=outdated|newest|devel|unique")
        args.append(f"{match_type}={pname}")
        try:
            df_repology_cli = repology_cli.query(
                repology.repology_cli.getargs(args),
                stdout_report=False,
                file_report=False,
            )
        except repology.exceptions.RepologyNoMatchingPackages:
            pass
        if df_repology_cli is None or df_repology_cli.empty:
            LOG.debug("No results from repology_cli")
            return None
        df_repology_cli = _select_newest(df_repology_cli)
        _repology_cli_dfs[pname] = df_repology_cli
        df_log(df_repology_cli, LOG_SPAM)
    return df_repology_cli


def _add_triage_item(out_dict, vuln, whitelist_cols, df_repo=None):
    if df_repo is None:
        out_dict.setdefault("vuln_id", []).append(vuln.vuln_id)
        out_dict.setdefault("url", []).append(vuln.url)
        out_dict.setdefault("package", []).append(vuln.package)
        out_dict.setdefault("severity", []).append(vuln.severity)
        out_dict.setdefault("version_local", []).append(vuln.version)
        out_dict.setdefault("version_nixpkgs", []).append("")
        out_dict.setdefault("version_upstream", []).append("")
        out_dict.setdefault("package_repology", []).append("")
        out_dict.setdefault("sortcol", []).append(vuln.sortcol)
        if whitelist_cols:
            out_dict.setdefault("whitelist", []).append(vuln.whitelist)
            out_dict.setdefault("whitelist_comment", []).append(vuln.whitelist_comment)
        return
    for item in df_repo.itertuples():
        out_dict.setdefault("vuln_id", []).append(vuln.vuln_id)
        out_dict.setdefault("url", []).append(vuln.url)
        out_dict.setdefault("package", []).append(vuln.package)
        out_dict.setdefault("severity", []).append(vuln.severity)
        out_dict.setdefault("version_local", []).append(vuln.version)
        out_dict.setdefault("version_nixpkgs", []).append(item.version)
        if item.newest_upstream_release and ";" in item.newest_upstream_release:
            version_upstream_str = item.newest_upstream_release.split(";")[0]
        else:
            version_upstream_str = item.newest_upstream_release
        out_dict.setdefault("version_upstream", []).append(version_upstream_str)
        out_dict.setdefault("package_repology", []).append(item.package)
        out_dict.setdefault("sortcol", []).append(vuln.sortcol)
        if whitelist_cols:
            out_dict.setdefault("whitelist", []).append(vuln.whitelist)
            out_dict.setdefault("whitelist_comment", []).append(vuln.whitelist_comment)


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
    wcols = "whitelist" in df_vuln_pkgs.columns
    for vuln in df_vuln_pkgs.itertuples():
        if wcols and vuln.whitelist:
            # Skip repology query for whitelisted vulnerabilities
            LOG.log(LOG_SPAM, "Whitelisted, skipping repology query: %s", vuln)
            _add_triage_item(result_dict, vuln, wcols)
            continue
        repo_pkg = nix_to_repology_pkg_name(vuln.package)
        LOG.log(LOG_SPAM, "Package '%s' ==> '%s'", vuln.package, repo_pkg)
        df_repology_cli = _run_repology_cli(repo_pkg)
        if df_repology_cli is not None and not df_repology_cli.empty:
            # If there's one match, there's no need to check other details
            if df_repology_cli.shape[0] == 1:
                LOG.log(LOG_SPAM, "One repology package matches")
                _add_triage_item(result_dict, vuln, wcols, df_repology_cli)
                continue
            # Match based on version: exact match
            df = df_repology_cli[df_repology_cli["version"] == vuln.version]
            if not df.empty:
                LOG.log(LOG_SPAM, "Exact version match '%s'", vuln.version)
                _add_triage_item(result_dict, vuln, wcols, df)
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
                _add_triage_item(result_dict, vuln, wcols, df)
                continue
            # Otherwise, we need to conclude that we don't know which repology
            # package (as returned by _run_repology_cli()), the nix package
            # 'vuln.package' maps to.
            # If we end up here, we could improve by doing another search with:
            # _run_repology_cli(repo_pkg, match_type='--pkg_search')
            LOG.log(LOG_SPAM, "Vague match in repology pkg, adding vuln only")
            _add_triage_item(result_dict, vuln, wcols)
        else:
            _add_triage_item(result_dict, vuln, wcols)
    df_result = pd.DataFrame(result_dict)
    df_result.fillna("", inplace=True)
    df_result.reset_index(drop=True, inplace=True)
    return df_result
