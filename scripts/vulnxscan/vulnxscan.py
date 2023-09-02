#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name, import-error, too-many-arguments
# pylint: disable=singleton-comparison

""" Demonstrate vulnerability scan with vulnix, grype, and osv.py"""

import argparse
import logging
import os
import sys
import pathlib
import json
import re
from tempfile import NamedTemporaryFile
from shutil import which
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
    exit_unless_nix_artifact,
    df_log,
)

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = (
        "Scan nix artifact or CycloneDX SBOM for vulnerabilities with grype, "
        "osv.py, and vulnix."
    )
    epil = f"Example: ./{os.path.basename(__file__)} /path/to/nix/out/or/drv"
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
        "accordingly in the output csv."
    )
    parser.add_argument("--whitelist", help=helps, type=pathlib.Path)
    return parser.parse_args()


################################################################################


class VulnScan:
    """Run vulnerability scans, generate reports"""

    def __init__(self):
        self.df_vulnix = None
        self.df_grype = None
        self.df_osv = None
        self.df_report = None

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
        if ret:
            self._parse_grype(ret)

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

    def report(self, args, sbom_csv):
        """Generate the vulnerability report: csv file and a table to console"""
        self._generate_report()
        if self.df_report is None or self.df_report.empty:
            LOG.info("No vulnerabilities found")
            return
        if sbom_csv:
            self._filter_patched(sbom_csv)
        if args.whitelist:
            LOG.info("Applying whitelist '%s'", args.whitelist)
            self._apply_whitelist(args.whitelist)
        LOG.debug("Writing report")

        # Console report
        # Copy the df to only make changes to the console report
        df = self.df_report.copy()
        # Don't print the "sortcol"
        df.drop("sortcol", inplace=True, axis=1)
        # Don't print whitelisted entries to the console report
        df = df_drop_whitelisted(df)
        if df.empty:
            LOG.info("Whitelisted all vulnerabilities")
        else:
            # Truncate
            df["version"] = df["version"].str.slice(0, 16)
            table = tabulate(
                df,
                headers="keys",
                tablefmt="orgtbl",
                numalign="center",
                showindex=False,
            )
            if args.sbom:
                end = f"components in '{args.TARGET}'"
            elif args.buildtime:
                end = (
                    f"'{args.TARGET}' or some of its runtime or buildtime dependencies"
                )
            else:
                end = f"'{args.TARGET}' or some of its runtime dependencies"
            header = f"Potential vulnerabilities impacting {end}:"
            LOG.info("Console report\n\n%s\n\n%s\n", header, table)

        # File report
        df_to_csv_file(self.df_report, args.out)


################################################################################


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
    if the whitelist not a valid vulnerability whitelist. Otherwise
    returns whitelist_csv_path as dataframe.
    """
    try:
        df = df_from_csv_file(whitelist_csv_path)
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
    except pd.errors.ParserError:
        return None


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


################################################################################

if __name__ == "__main__":
    main()

################################################################################
