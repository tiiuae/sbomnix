#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name, import-error

""" Demonstrate vulnerability scan with vulnix, grype, and osv.py"""

import argparse
import logging
import os
import sys
import pathlib
import json
import re
import pandas as pd
import numpy as np
from tabulate import tabulate
from sbomnix.utils import (
    setup_logging,
    exec_cmd,
    LOGGER_NAME,
    LOG_SPAM,
    df_from_csv_file,
    df_to_csv_file,
)

###############################################################################

_LOG = logging.getLogger(LOGGER_NAME)

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = "Scan nix artifact for vulnerabilities with vulnix, grype, and osv.py"
    epil = f"Example: ./{os.path.basename(__file__)} /path/to/sbom.json"
    parser = argparse.ArgumentParser(description=desc, epilog=epil)
    helps = "Target derivation path or nix out path"
    parser.add_argument("TARGET", help=helps, type=pathlib.Path)
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)
    helps = "Path to output file (default: ./vulns.csv)"
    parser.add_argument("--out", nargs="?", help=helps, default="vulns.csv")
    helps = (
        "Include target's buildtime dependencies to the scan."
        "By default, only runtime dependencies are scanned."
    )
    parser.add_argument("--buildtime", help=helps, action="store_true")
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
            _LOG.debug("Vulnix found vulnerabilities")
            self.df_vulnix.replace(np.nan, "", regex=True, inplace=True)
            self.df_vulnix.drop_duplicates(keep="first", inplace=True)
            if _LOG.level <= logging.DEBUG:
                df_to_csv_file(self.df_vulnix, "df_vulnix.csv")

    def scan_vulnix(self, target_path, buildtime=False):
        """Run vulnix scan for nix artifact at target_path"""
        _LOG.info("Running vulnix scan")
        # We use vulnix from 'https://github.com/henrirosten/vulnix' to get
        # vulnix support for runtime-only scan ('-C' command-line option)
        # which is currently not available in released version of vulnix.
        # To manually test this on command-line, try something like:
        # nix-shell \
        #   --packages 'callPackage (fetchGit { url = URL; ref = "master"; } ) {}' \
        #   --run "vulnix PATH_TO_TARGET -C --json"
        url = "https://github.com/henrirosten/vulnix"
        ref = '"master"'
        packages = f"callPackage (fetchGit {{ url = {url}; ref = {ref}; }} ) {{}}"
        extra_opts = "-C --json"
        if buildtime:
            extra_opts = "--json"
        run_vulnix = f"vulnix {target_path} {extra_opts}"
        cmd = ["nix-shell", "--packages", packages, "--run", run_vulnix]
        # vulnix exit status is non-zero if it found vulnerabilities,
        # therefore, we need to set the raise_on_error=False and
        # return_error=True to be able to read the command's stdout on
        # failure
        ret = exec_cmd(cmd, raise_on_error=False, return_error=True)
        if ret and hasattr(ret, "stdout") and ret.stdout:
            self._parse_vulnix(ret.stdout)

    def _parse_grype(self, json_str):
        vulnerabilities = json.loads(json_str)
        _LOG.log(LOG_SPAM, json.dumps(vulnerabilities, indent=2))
        grype_vulns_dict = {}
        setcol = grype_vulns_dict.setdefault
        for vuln in vulnerabilities["matches"]:
            if not vuln["artifact"]["version"]:
                _LOG.log(
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
            _LOG.debug("Grype found vulnerabilities")
            self.df_grype.replace(np.nan, "", regex=True, inplace=True)
            self.df_grype.drop_duplicates(keep="first", inplace=True)
            if _LOG.level <= logging.DEBUG:
                df_to_csv_file(self.df_grype, "df_grype.csv")

    def scan_grype(self, sbom_path):
        """Run grype scan using the SBOM at sbom_path as input"""
        _LOG.info("Running grype scan")
        # To manually test this on command-line, try something like:
        # nix-shell \
        #   --packages grype \
        #   --run "grype sbom:PATH_TO_SBOM --add-cpes-if-none --output json"
        packages = "grype"
        extra_opts = "--add-cpes-if-none --output json"
        run_grype = f"grype sbom:{sbom_path} {extra_opts}"
        cmd = ["nix-shell", "--packages", packages, "--run", run_grype]
        ret = exec_cmd(cmd)
        if ret:
            self._parse_grype(ret)

    def _parse_osv(self, osv_out_path):
        self.df_osv = df_from_csv_file(osv_out_path)
        if not self.df_osv.empty:
            self.df_osv["scanner"] = "osv"
            self.df_osv.replace(np.nan, "", regex=True, inplace=True)
            self.df_osv.drop_duplicates(keep="first", inplace=True)
            self.df_osv["modified"] = pd.to_datetime(self.df_osv["modified"])
            _LOG.log(LOG_SPAM, "osv data:\n%s", self.df_osv.to_markdown())
            _LOG.debug("OSV scan found vulnerabilities")
            if _LOG.level <= logging.DEBUG:
                df_to_csv_file(self.df_osv, "df_osv.csv")

    def scan_osv(self, sbom_path):
        """Run osv scan using the SBOM at sbom_path as input"""
        _LOG.info("Running OSV scan")
        osv_scanner = pathlib.Path(__file__).parents[0] / "osv.py"
        osv_out = pathlib.Path("osv_vulns.csv")
        cmd = f"{osv_scanner.as_posix()} " f"--out {osv_out.as_posix()} " f"{sbom_path}"
        exec_cmd(cmd.split(), raise_on_error=True)
        if _valid_csv(osv_out):
            self._parse_osv(osv_out.as_posix())

    def _generate_report(self):
        # Concatenate vulnerability data from different scanners
        df = pd.concat([self.df_vulnix, self.df_grype, self.df_osv], ignore_index=True)
        if df.empty:
            _LOG.debug("No scanners reported any findings")
            return
        # Add column 'sortcol'
        df["sortcol"] = df.apply(_vuln_sortcol, axis=1)
        if _LOG.level <= logging.DEBUG:
            df_to_csv_file(df, "df_report_raw.csv")

        # Following steps summarize the raw data to produce df_report

        # We'll use the following column to aggregate values in the pivot table
        df["count"] = 1
        # Group by the following columns making "scanner" values new columns
        group_cols = ["vuln_id", "package", "version", "sortcol"]
        df = df.pivot_table(index=group_cols, columns="scanner", values="count")
        # Pivot creates a multilevel index, we'll get rid of it:
        df.reset_index(drop=False, inplace=True)
        scanners = ["grype", "osv", "vulnix"]
        df.reindex(group_cols + scanners, axis=1)
        for scanner_col in scanners:
            if scanner_col not in df:
                df[scanner_col] = 0
        # Add 'sum' column
        df["sum"] = df[scanners].sum(axis=1).astype(int)
        # Reformat values in 'scanner' columns
        df["grype"] = df.apply(lambda row: _reformat_scanner(row.grype), axis=1)
        df["osv"] = df.apply(lambda row: _reformat_scanner(row.osv), axis=1)
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

    def report(self, name, target, buildtime):
        """Generate the vulnerability report: csv file and a table to console"""
        self._generate_report()
        if self.df_report is None or self.df_report.empty:
            _LOG.info("No vulnerabilities found")
            return
        _LOG.info("Writing report")

        # Console report
        # Copy the df to only make changes to the console report
        df = self.df_report.copy()
        # Don't print the "sortcol"
        df = df.drop("sortcol", axis=1)
        # Truncate
        df["version"] = df["version"].str.slice(0, 16)
        table = tabulate(
            df, headers="keys", tablefmt="orgtbl", numalign="center", showindex=False
        )
        dtype = "runtime or buildtime" if buildtime else "runtime"
        header = (
            f"Potential vulnerabilities impacting '{target}' or some of its "
            f"{dtype} dependencies:"
        )
        _LOG.info("Console report:\n\n%s\n\n%s\n", header, table)

        # File report
        df_to_csv_file(self.df_report, name)


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


def _valid_csv(path):
    try:
        pd.read_csv(path, nrows=1)
        _LOG.debug("True")
        return True
    except (FileNotFoundError, pd.errors.EmptyDataError, pd.errors.ParserError):
        _LOG.debug("False")
        return False


def _check_nix():
    _LOG.info("Checking nix installation")
    # Try running nix-info to check that nix tools are available
    cmd = "nix-shell -p nix-info --run 'nix-info'"
    ret = exec_cmd(cmd.split(), raise_on_error=True)
    _LOG.debug(ret.strip())


def _generate_sbom(target_path, buildtime=False):
    _LOG.info("Generating SBOM for target '%s'", target_path)
    sbomnix = pathlib.Path(__file__).parents[2] / "sbomnix" / "main.py"
    sbomtype = "runtime"
    cdx = pathlib.Path("sbom_cdx.json")
    if buildtime:
        sbomtype = "both"
    cmd = f"{sbomnix.as_posix()} --type {sbomtype} {target_path} --cdx={cdx.as_posix()}"
    ret = exec_cmd(cmd.split(), raise_on_error=True)
    _LOG.debug(ret.strip())
    if not cdx.exists():
        _LOG.fatal("Failed generating SBOM")
        sys.exit(1)
    return cdx.as_posix()


################################################################################


def main():
    """main entry point"""
    args = getargs()
    setup_logging(args.verbose)
    if not args.TARGET.exists():
        _LOG.fatal("Invalid path: '%s'", args.TARGET)
        sys.exit(1)
    _check_nix()
    target_path = args.TARGET.as_posix()
    sbom_path = _generate_sbom(target_path, args.buildtime)

    scanner = VulnScan()
    scanner.scan_vulnix(target_path, args.buildtime)
    scanner.scan_grype(sbom_path)
    scanner.scan_osv(sbom_path)
    scanner.report(args.out, target_path, args.buildtime)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
