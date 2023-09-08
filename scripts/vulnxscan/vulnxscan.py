#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name, import-error, too-many-arguments
# pylint: disable=singleton-comparison, abstract-method
# pylint: disable=too-many-return-statements

"""
Scan nix artifact or CycloneDX SBOM for vulnerabilities with various
open-source vulnerability scanners.
"""


import argparse
import logging
import sys
import pathlib
import json
import re
import time
import urllib.parse
from tempfile import NamedTemporaryFile
from shutil import which

from requests import Session
from requests_cache import CacheMixin
from requests_ratelimiter import LimiterMixin
import pandas as pd
import numpy as np

from tabulate import tabulate
from scripts.vulnxscan.osv import OSV
from sbomnix.sbomdb import SbomDb
from sbomnix.utils import (
    LOG,
    LOG_SPAM,
    set_log_verbosity,
    exec_cmd,
    df_to_csv_file,
    df_from_csv_file,
    df_log,
    exit_unless_nix_artifact,
    nix_to_repology_pkg_name,
    parse_version,
    version_distance,
)

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = (
        "Scan nix artifact or CycloneDX SBOM for vulnerabilities with "
        "various open-source vulnerability scanners."
    )
    epil = "Example: ./vulnxscan.py /path/to/nix/out/or/drv"
    parser = argparse.ArgumentParser(description=desc, epilog=epil)
    helps = "Target derivation path or nix out path"
    parser.add_argument("TARGET", help=helps, type=pathlib.Path)
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)
    helps = "Path to output file (default: ./vulns.csv)"
    parser.add_argument("--out", nargs="?", help=helps, default="vulns.csv")
    helps = (
        "Scan target buildtime instead of runtime dependencies. This option "
        "has no impact if the scan target is SBOM (ref: --sbom)."
    )
    parser.add_argument("--buildtime", help=helps, action="store_true")
    helps = (
        "Indicate that TARGET is a cdx SBOM instead of path to nix artifact. "
        "This allows running vulnxscan using input SBOMs from any tool "
        "capable of generating cdx SBOM. This option makes it possible to run "
        "vulnxscan postmortem against any (potentially earlier) release of "
        "the TARGET. "
        "Moreover, this option allows using vulnxscan against non-nix targets "
        "as long as SBOM includes valid CPE identifiers and purls. "
        "If this option is specified, vulnix scan will not run, since vulnix "
        "is nix-only and requires components' nix store paths. "
        "Also, if this option is specified, option '--buildtime' will be "
        "ignored since target pacakges will be read from the given SBOM."
    )
    parser.add_argument("--sbom", help=helps, action="store_true")
    helps = (
        "Path to whitelist file. Vulnerabilities that match any whitelisted "
        "entries will not be included to the console output and are annotated "
        "accordingly in the output csv. See more details in the vulnxscan "
        "README.md."
    )
    parser.add_argument("--whitelist", help=helps, type=pathlib.Path)
    helps = (
        "Add more information to vulnxscan output by querying "
        "repology.org for available package versions in nix-unstable and "
        "package upstream. This option is intended to help manual analysis. "
        "Output is written to a separate OUT file with 'triage' infix, "
        "by default: 'vulns.triage.csv'."
    )
    parser.add_argument("--triage", help=helps, action="store_true")
    triagegr = parser.add_argument_group("Other arguments")
    helps = (
        "Search nixpkgs github for PRs that might include more information "
        "concerning possible nixpkgs fixes for the found vulnerabilities. "
        "This option adds URLs to (at most five) PRs that appear valid "
        "for each vulnerability based on heuristic. "
        "The PR search takes significant "
        "time due to github API rate limits, which is why this feature is "
        "not enabled by default. This option has no impact unless '--triage' "
        "is also specified."
    )
    triagegr.add_argument("--nixprs", help=helps, action="store_true")
    return parser.parse_args()


################################################################################

# Scanner


class VulnScan:
    """Run vulnerability scans, generate reports"""

    def __init__(self):
        self.df_vulnix = None
        self.df_grype = None
        self.df_osv = None
        self.df_report = None
        self.df_triaged = None

    def _parse_vulnix(self, json_str):
        vulnerable_packages = json.loads(json_str)
        vulnix_vulns_dict = {}
        setcol = vulnix_vulns_dict.setdefault
        for package in vulnerable_packages:
            for cve in package["affected_by"]:
                setcol("package", []).append(package["pname"])
                setcol("version", []).append(package["version"])
                setcol("vuln_id", []).append(cve)
                setcol("scanner", []).append("vulnix")
        self.df_vulnix = pd.DataFrame.from_dict(vulnix_vulns_dict)
        if not self.df_vulnix.empty:
            LOG.debug("Vulnix found vulnerabilities")
            self.df_vulnix.replace(np.nan, "", regex=True, inplace=True)
            self.df_vulnix.drop_duplicates(keep="first", inplace=True)
            if LOG.level <= logging.DEBUG:
                df_to_csv_file(self.df_vulnix, "df_vulnix.csv")

    def scan_vulnix(self, target_path, buildtime=False):
        """Run vulnix scan for nix artifact at target_path"""
        LOG.info("Running vulnix scan")
        self.df_vulnix = pd.DataFrame()
        extra_opts = "-C --json"
        if buildtime:
            extra_opts = "--json"
        cmd = ["vulnix", target_path] + extra_opts.split()
        # vulnix exit status is non-zero if it found vulnerabilities.
        # Therefore, we need to set the raise_on_error=False and
        # return_error=True to be able to read the vulnerabilities
        # from vulnix stdout even if the exit status indicates failure.
        ret = exec_cmd(cmd, raise_on_error=False, return_error=True)
        if ret and hasattr(ret, "stderr") and ret.stderr:
            LOG.warning(ret)
            LOG.warning(ret.stderr)
            self.df_vulnix = None
        elif ret and hasattr(ret, "stdout") and ret.stdout:
            self._parse_vulnix(ret.stdout)

    def _parse_grype(self, json_str):
        vulnerabilities = json.loads(json_str)
        LOG.log(LOG_SPAM, json.dumps(vulnerabilities, indent=2))
        grype_vulns_dict = {}
        setcol = grype_vulns_dict.setdefault
        for vuln in vulnerabilities["matches"]:
            if not vuln["artifact"]["version"]:
                LOG.log(
                    LOG_SPAM,
                    "'%s' missing version information: skipping",
                    vuln["artifact"]["name"],
                )
                continue
            setcol("package", []).append(vuln["artifact"]["name"])
            setcol("version", []).append(vuln["artifact"]["version"])
            setcol("vuln_id", []).append(vuln["vulnerability"]["id"])
            setcol("scanner", []).append("grype")
        self.df_grype = pd.DataFrame.from_dict(grype_vulns_dict)
        if not self.df_grype.empty:
            LOG.debug("Grype found vulnerabilities")
            self.df_grype.replace(np.nan, "", regex=True, inplace=True)
            self.df_grype.drop_duplicates(keep="first", inplace=True)
            if LOG.level <= logging.DEBUG:
                df_to_csv_file(self.df_grype, "df_grype.csv")

    def scan_grype(self, sbom_path):
        """Run grype scan using the SBOM at sbom_path as input"""
        LOG.info("Running grype scan")
        cmd = ["grype", f"sbom:{sbom_path}", "--add-cpes-if-none", "--output", "json"]
        ret = exec_cmd(cmd)
        if ret.stdout:
            self._parse_grype(ret.stdout)

    def _parse_osv(self, df_osv):
        self.df_osv = df_osv
        if not self.df_osv.empty:
            self.df_osv["scanner"] = "osv"
            self.df_osv.replace(np.nan, "", regex=True, inplace=True)
            self.df_osv.drop_duplicates(keep="first", inplace=True)
            self.df_osv["modified"] = pd.to_datetime(
                self.df_osv["modified"], format="%Y-%m-%d", exact=False
            )
            LOG.log(LOG_SPAM, "osv data:\n%s", self.df_osv.to_markdown())
            LOG.debug("OSV scan found vulnerabilities")
            if LOG.level <= logging.DEBUG:
                df_to_csv_file(self.df_osv, "df_osv.csv")

    def scan_osv(self, sbom_path):
        """Run osv scan using the SBOM at sbom_path as input"""
        LOG.info("Running OSV scan")
        osv = OSV()
        osv.query_vulns(sbom_path)
        df_osv = osv.to_dataframe()
        self._parse_osv(df_osv)

    def _generate_report(self):
        # Concatenate vulnerability data from different scanners
        df = pd.concat([self.df_vulnix, self.df_grype, self.df_osv], ignore_index=True)
        if df.empty:
            LOG.debug("No scanners reported any findings")
            return
        # Add column 'sortcol'
        df["sortcol"] = df.apply(_vuln_sortcol, axis=1)
        if LOG.level <= logging.DEBUG:
            df_to_csv_file(df, "df_report_raw.csv")

        # Following steps summarize the raw data to produce df_report

        # We'll use the following column to aggregate values in the pivot table
        df["count"] = 1
        # Group by the following columns making "scanner" values new columns
        group_cols = ["vuln_id", "package", "version", "sortcol"]
        df = df.pivot_table(index=group_cols, columns="scanner", values="count")
        # Pivot creates a multilevel index, we'll get rid of it:
        df.reset_index(drop=False, inplace=True)
        scanners = ["grype", "osv"]
        if self.df_vulnix is not None:
            scanners.append("vulnix")
        df.reindex(group_cols + scanners, axis=1)
        for scanner_col in scanners:
            if scanner_col not in df:
                df[scanner_col] = 0
        # Add 'sum' column
        df["sum"] = df[scanners].sum(axis=1).astype(int)
        # Reformat values in 'scanner' columns
        df["grype"] = df.apply(lambda row: _reformat_scanner(row.grype), axis=1)
        df["osv"] = df.apply(lambda row: _reformat_scanner(row.osv), axis=1)
        if "vulnix" in scanners:
            df["vulnix"] = df.apply(lambda row: _reformat_scanner(row.vulnix), axis=1)
        # Add column 'url'
        df["url"] = df.apply(_vuln_url, axis=1)
        # Sort the data based on the following columns
        sort_cols = ["sortcol", "package", "version"]
        df.sort_values(by=sort_cols, ascending=False, inplace=True)
        # Re-order columns
        report_cols = (
            ["vuln_id", "url", "package", "version"] + scanners + ["sum", "sortcol"]
        )
        self.df_report = df[report_cols]

    def _filter_patched(self, sbom_csv):
        LOG.info("Filtering patched vulnerabilities")
        df_sbom_csv = df_from_csv_file(sbom_csv)
        df = pd.merge(
            left=self.df_report,
            right=df_sbom_csv,
            how="left",
            left_on=["package", "version"],
            right_on=["pname", "version"],
            suffixes=["", "_sbom_csv"],
        )
        df["patched"] = df.apply(_is_patched, axis=1)
        # Only keep the rows where 'patched' is False
        df = df[~df["patched"]]
        # Keep only the columns from the original report
        df = df[self.df_report.columns.values]
        # Drop possible duplicates generated by the merge
        self.df_report = df.drop_duplicates(keep="first")

    def _apply_whitelist(self, whitelist_csv):
        if whitelist_csv is None:
            return
        df_whitelist = load_whitelist(whitelist_csv)
        if df_whitelist is None:
            return
        df_apply_whitelist(df_whitelist, self.df_report)

    def _console_report(self):
        LOG.debug("")
        # Copy the df to not make changes to the original dataframe
        if self.df_triaged is not None:
            df = self.df_triaged.copy()
            df = df.drop("package_repology", axis=1)
        else:
            df = self.df_report.copy()
        # Don't print the following columns to console
        df = df.drop("sortcol", axis=1)
        #  Don't print whitelisted entries to the console report
        df = df_drop_whitelisted(df)
        if df.empty:
            LOG.info("Whitelisted all vulnerabilities")
            return
        # Truncate version columns
        version_cols = [col for col in df.columns if "version" in col]
        for col in version_cols:
            df[col] = df[col].str.slice(0, 16)
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
            "Potential vulnerabilities impacting version_local: "
            "\n\n%s\n\n",
            table,
        )

    def report(self, args, sbom_csv):
        """Generate the vulnerability reports: csv file and a table to console"""
        self._generate_report()
        if self.df_report is None or self.df_report.empty:
            LOG.info("No vulnerabilities found")
            return
        if sbom_csv:
            self._filter_patched(sbom_csv)
        if args.whitelist:
            LOG.info("Applying whitelist '%s'", args.whitelist)
            self._apply_whitelist(args.whitelist)
        if args.triage:
            LOG.info("Running vulnerability triage")
            self.df_triaged = _triage(self.df_report, args.nixprs)
        # Rename 'version' to 'version_local'
        self.df_report.rename(columns={"version": "version_local"}, inplace=True)

        LOG.debug("Writing reports")
        # Console report
        self._console_report()
        # File report
        out = pathlib.Path(args.out)
        df_to_csv_file(self.df_report, out.resolve().as_posix())
        if args.triage:
            parents = out.parents[0].resolve().as_posix()
            triage_out = f"{parents}/{out.stem}.triage{out.suffix}"
            df_to_csv_file(self.df_triaged, triage_out)


################################################################################

# Triage


class CachedLimiterSession(CacheMixin, LimiterMixin, Session):
    """Session class with caching and rate-limiting"""


_repology_cve_dfs = {}
_repology_cli_dfs = {}
_repology_nix_repo = "nix_unstable"
# Rate-limited and cached session. For github api rate limits, see:
# https://docs.github.com/en/rest/search?apiVersion=latest#rate-limit
_session = CachedLimiterSession(per_minute=9, per_second=1, expire_after=7200)


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
            df_repology_cli = df_from_csv_file(f.name, exit_on_error=False)
            if df_repology_cli is None:
                return None
            df_repology_cli = _select_newest(df_repology_cli)
            _repology_cli_dfs[pname] = df_repology_cli
            df_log(df_repology_cli, LOG_SPAM)
    return df_repology_cli


def _add_vuln_item(out_dict, vuln, whitelist_cols, df_repo=None):
    if df_repo is None:
        out_dict.setdefault("vuln_id", []).append(vuln.vuln_id)
        out_dict.setdefault("url", []).append(vuln.url)
        out_dict.setdefault("package", []).append(vuln.package)
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
            _add_vuln_item(result_dict, vuln, wcols)
            continue
        repo_pkg = nix_to_repology_pkg_name(vuln.package)
        LOG.log(LOG_SPAM, "Package '%s' ==> '%s'", vuln.package, repo_pkg)
        df_repology_cli = _run_repology_cli(repo_pkg)
        if df_repology_cli is not None and not df_repology_cli.empty:
            # If there's one match, there's no need to check other details
            if df_repology_cli.shape[0] == 1:
                LOG.log(LOG_SPAM, "One repology package matches")
                _add_vuln_item(result_dict, vuln, wcols, df_repology_cli)
                continue
            # Match based on version: exact match
            df = df_repology_cli[df_repology_cli["version"] == vuln.version]
            if not df.empty:
                LOG.log(LOG_SPAM, "Exact version match '%s'", vuln.version)
                _add_vuln_item(result_dict, vuln, wcols, df)
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
                _add_vuln_item(result_dict, vuln, wcols, df)
                continue
            # Otherwise, we need to conclude that we don't know which repology
            # package (as returned by _run_repology_cli()), the nix package
            # 'vuln.package' maps to.
            # If we end up here, we could improve by doing another search with:
            # _run_repology_cli(repo_pkg, match_type='--pkg_search')
            LOG.log(LOG_SPAM, "Vague match in repology pkg, adding vuln only")
            _add_vuln_item(result_dict, vuln, wcols)
        else:
            _add_vuln_item(result_dict, vuln, wcols)
    df_result = pd.DataFrame(result_dict)
    df_result.fillna("", inplace=True)
    df_result.reset_index(drop=True, inplace=True)
    return df_result


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
            df = df_from_csv_file(f.name, exit_on_error=False)
            if df is None:
                df = pd.DataFrame()
            df_log(df, LOG_SPAM)
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


def _triage(df_report, search_nix_prs):
    LOG.debug("")
    df = df_report.copy()
    uids = ["vuln_id", "package", "version", "url", "sortcol"]
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
    sort_cols = ["sortcol", "package", "version_local"]
    df_vuln_pkgs.sort_values(by=sort_cols, ascending=False, inplace=True)
    return df_vuln_pkgs


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


def _generate_sbom(target_path, runtime=True, buildtime=False):
    LOG.info("Generating SBOM for target '%s'", target_path)
    sbomdb = SbomDb(target_path, runtime, buildtime, meta_path=None)
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
        return fcdx.name, fcsv.name


def _is_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            json_obj = json.load(f)
            if json_obj:
                return True
            return False
    except (json.JSONDecodeError, OSError, UnicodeError):
        return False


def _exit_unless_command_exists(name):
    """Check if `name` is an executable in PATH"""
    name_is_in_path = which(name) is not None
    if not name_is_in_path:
        LOG.fatal("command '%s' is not in PATH", name)
        sys.exit(1)


################################################################################

# Whitelist


def load_whitelist(whitelist_csv_path):
    """
    Load vulnerability whitelist from the given path. Returns None
    if the whitelist is not a valid vulnerability whitelist. Otherwise
    returns whitelist_csv_path as dataframe.
    """
    df = df_from_csv_file(whitelist_csv_path, exit_on_error=False)
    if df is None:
        return None
    # Whitelist must have the following columns
    if not set(["vuln_id", "comment"]).issubset(df.columns):
        LOG.warning("Whitelist csv missing required columns")
        return None
    if "whitelist" in df.columns:
        # Interpret possible string values in "whitelist" column
        # to boolean as follows:
        df["whitelist"] = df["whitelist"].replace({"": True})
        df["whitelist"] = df["whitelist"].replace({"False": False, "0": False})
        df["whitelist"] = df["whitelist"].astype("bool")
    return df


def df_apply_whitelist(df_whitelist, df_vulns):
    """
    Apply df_whitelist to vulnerabilities in df_vulns, changing df_vulns
    in-place.
    Adds columns "whitelist" and "whitelist_comment" to df_vulns based
    on whitelisting regular expressions in column df_whitelist["vuln_id"].
    If df_whitelist["package"] exists and is not empty, require strict
    match in df_whitelist["package"] and df_vulns["package"].
    If df_whitelist["whitelist"] exists and is False, do *not* whitelist
    the entry even if the rule matches, but only apply the column
    "whitelist_comment" to matching entries.
    """
    # Add default values to whitelist columns
    df_vulns["whitelist"] = False
    df_vulns["whitelist_comment"] = ""
    if "vuln_id" not in df_vulns:
        LOG.fatal("Missing 'vuln_id' column from df_vulns")
        sys.exit(1)
    if "vuln_id" not in df_whitelist:
        LOG.warning("Whitelist ignored: missing 'vuln_id' column from whitelist")
        return
    check_pkg_name = False
    if "package" in df_whitelist.columns and "package" in df_vulns.columns:
        check_pkg_name = True
    check_whitelist = False
    if "whitelist" in df_whitelist.columns:
        check_whitelist = True
    # Iterate rows in df_whitelist in reverse order so the whitelist rules
    # on top of the file get higher priority
    df_whitelist_rev = df_whitelist[::-1]
    for whitelist_entry in df_whitelist_rev.itertuples():
        LOG.log(LOG_SPAM, "whitelist_entry: %s", whitelist_entry)
        regex = str(whitelist_entry.vuln_id).strip()
        LOG.log(LOG_SPAM, "whitelist regex: %s", regex)
        df_matches = df_vulns["vuln_id"].str.fullmatch(regex)
        if check_pkg_name and whitelist_entry.package:
            LOG.log(LOG_SPAM, "filtering by pacakge name: %s", whitelist_entry.package)
            df_matches = df_matches & (df_vulns["package"] == whitelist_entry.package)
        df_vulns.loc[df_matches, "whitelist"] = True
        if check_whitelist:
            LOG.log(LOG_SPAM, "entry[whitelist]=%s", bool(whitelist_entry.whitelist))
            df_vulns.loc[df_matches, "whitelist"] = bool(whitelist_entry.whitelist)
        df_vulns.loc[df_matches, "whitelist_comment"] = whitelist_entry.comment
        LOG.log(LOG_SPAM, "matches %s vulns", len(df_vulns[df_matches]))
        df_log(df_vulns[df_matches], LOG_SPAM)


def df_drop_whitelisted(df):
    """
    Drop whitelisted vulnerabilities from `df` as well as
    the related columns.
    """
    if "whitelist" in df.columns:
        # Convert possible string to boolean
        df = df[~df["whitelist"]]
        df = df.drop("whitelist", axis=1)
    if "whitelist_comment" in df.columns:
        df = df.drop("whitelist_comment", axis=1)
    return df


################################################################################

# Main


def main():
    """main entry point"""
    args = getargs()
    set_log_verbosity(args.verbose)

    # Fail early if following commands are not in path
    _exit_unless_command_exists("grype")
    _exit_unless_command_exists("vulnix")

    target_path_abs = args.TARGET.resolve().as_posix()
    scanner = VulnScan()
    if args.sbom:
        if not _is_json(target_path_abs):
            LOG.fatal(
                "Specified sbom target is not a json file: '%s'", str(args.TARGET)
            )
            sys.exit(0)
        sbom_cdx_path = target_path_abs
        sbom_csv_path = None
    else:
        runtime = args.buildtime is False
        exit_unless_nix_artifact(target_path_abs, force_realise=runtime)
        sbom_cdx_path, sbom_csv_path = _generate_sbom(
            target_path_abs, runtime, args.buildtime
        )
        LOG.info("Using cdx SBOM '%s'", sbom_cdx_path)
        LOG.info("Using csv SBOM '%s'", sbom_csv_path)
        scanner.scan_vulnix(target_path_abs, args.buildtime)
    scanner.scan_grype(sbom_cdx_path)
    scanner.scan_osv(sbom_cdx_path)
    scanner.report(args, sbom_csv_path)


if __name__ == "__main__":
    main()

################################################################################
