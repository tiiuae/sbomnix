#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""
VulnScan abstracts over querying and collecting vulnerability information
from grype, vulnix, and osv databases
"""

################################################################################

# Scanner

import json
import logging
import pathlib

import numpy as np
import pandas as pd
from tabulate import tabulate

from common.utils import (LOG, LOG_SPAM, df_from_csv_file, df_to_csv_file,
                          exec_cmd)
from vulnxscan.osv import OSV
from vulnxscan.utils import (_is_patched, _reformat_scanner, _triage,
                             _vuln_sortcol, _vuln_url)
from vulnxscan.whitelist import (df_apply_whitelist, df_drop_whitelisted,
                                 load_whitelist)


class VulnScan:
    """Run vulnerability scans, generate reports"""

    def __init__(self):
        self.df_vulnix = None
        self.df_grype = None
        self.df_osv = None
        self.df_report = None
        self.df_triaged = None
        # Key:vuln_id, value:severity
        self.cvss = {}

    def _parse_vulnix(self, json_str):
        vulnerable_packages = json.loads(json_str)
        vulnix_vulns_dict = {}
        setcol = vulnix_vulns_dict.setdefault
        for package in vulnerable_packages:
            cvss = package["cvssv3_basescore"]
            for cve in package["affected_by"]:
                severity = "" if cve not in self.cvss else self.cvss[cve]
                if not severity and cve in cvss:
                    severity = cvss[cve]
                    self.cvss[cve] = severity
                setcol("package", []).append(package["pname"])
                setcol("version", []).append(package["version"])
                setcol("vuln_id", []).append(cve)
                setcol("severity", []).append(severity)
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
            vid = vuln["vulnerability"]["id"]
            severity = "" if vid not in self.cvss else self.cvss[vid]
            if not severity and vuln["vulnerability"]["cvss"]:
                for cvss in vuln["vulnerability"]["cvss"]:
                    if float(cvss["version"]) >= 3:
                        LOG.log(LOG_SPAM, "selected cvss: %s", cvss)
                        severity = cvss["metrics"]["baseScore"]
                        self.cvss[vid] = severity
                        break
            setcol("package", []).append(vuln["artifact"]["name"])
            setcol("version", []).append(vuln["artifact"]["version"])
            setcol("vuln_id", []).append(vuln["vulnerability"]["id"])
            setcol("severity", []).append(severity)
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
            self.df_osv["severity"] = self.df_osv.apply(self._get_severity, axis=1)
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

    def _get_severity(self, row):
        if "vuln_id" not in row:
            return ""
        vuln_id = row.vuln_id
        severity = "" if vuln_id not in self.cvss else self.cvss[vuln_id]
        return severity

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
        group_cols = ["vuln_id", "package", "severity", "version", "sortcol"]
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
        sort_cols = ["sortcol", "package", "severity", "version"]
        df.sort_values(by=sort_cols, ascending=False, inplace=True)
        # Re-order columns
        report_cols = (
            ["vuln_id", "url", "package", "version", "severity"]
            + scanners
            + ["sum", "sortcol"]
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
