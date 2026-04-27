#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""
VulnScan abstracts over querying and collecting vulnerability information
from grype, vulnix, and osv databases
"""

import pandas as pd

from common import columns as cols
from common.df import df_to_csv_file
from common.log import LOG, LOG_SPAM, is_debug_enabled
from common.proc import exec_cmd
from vulnxscan import parsers as vulnxscan_parsers
from vulnxscan import reporting as vulnxscan_reporting
from vulnxscan import scanners as vulnxscan_scanners
from vulnxscan.triage import triage_vulnerabilities
from vulnxscan.utils import _vuln_sortcol


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
        self.df_vulnix = vulnxscan_parsers.parse_vulnix_json(
            json_str,
            cvss_cache=self.cvss,
            log=LOG,
        )
        if not self.df_vulnix.empty:
            if is_debug_enabled():
                df_to_csv_file(self.df_vulnix, "df_vulnix.csv")

    def scan_vulnix(self, target_path, buildtime=False):
        """Run vulnix scan for nix artifact at target_path"""
        self.df_vulnix = pd.DataFrame()
        ret = vulnxscan_scanners.run_vulnix_scan(
            target_path,
            buildtime=buildtime,
            exec_cmd_fn=exec_cmd,
            log=LOG,
        )
        if ret and hasattr(ret, "stderr") and ret.stderr:
            LOG.warning(ret)
            LOG.warning(ret.stderr)
            self.df_vulnix = None
        if ret and hasattr(ret, "stdout") and ret.stdout:
            self._parse_vulnix(ret.stdout)

    def _parse_grype(self, json_str):
        self.df_grype = vulnxscan_parsers.parse_grype_json(
            json_str,
            cvss_cache=self.cvss,
            log=LOG,
            log_spam=LOG_SPAM,
        )
        if not self.df_grype.empty:
            if is_debug_enabled():
                df_to_csv_file(self.df_grype, "df_grype.csv")

    def scan_grype(self, sbom_path):
        """Run grype scan using the SBOM at sbom_path as input"""
        ret = vulnxscan_scanners.run_grype_scan(
            sbom_path,
            exec_cmd_fn=exec_cmd,
            log=LOG,
        )
        if ret.stdout:
            self._parse_grype(ret.stdout)

    def _parse_osv(self, df_osv):
        self.df_osv = vulnxscan_parsers.normalize_osv_dataframe(
            df_osv,
            cvss_cache=self.cvss,
            log=LOG,
            log_spam=LOG_SPAM,
        )
        if not self.df_osv.empty:
            if is_debug_enabled():
                df_to_csv_file(self.df_osv, "df_osv.csv")

    def scan_osv(self, sbom_path):
        """Run osv scan using the SBOM at sbom_path as input"""
        df_osv = vulnxscan_scanners.run_osv_scan(sbom_path, log=LOG)
        self._parse_osv(df_osv)

    def _generate_report(self):
        self.df_report = vulnxscan_reporting.build_report_dataframe(
            self.df_vulnix,
            self.df_grype,
            self.df_osv,
            log=LOG,
        )
        if self.df_report.empty:
            self.df_report = None
            return
        if is_debug_enabled():
            df_report_raw = pd.concat(
                [
                    df
                    for df in [self.df_vulnix, self.df_grype, self.df_osv]
                    if df is not None
                ],
                ignore_index=True,
            )
            if not df_report_raw.empty:
                df_report_raw[cols.SORTCOL] = df_report_raw.apply(
                    _vuln_sortcol,
                    axis=1,
                )
                df_to_csv_file(df_report_raw, "df_report_raw.csv")

    def _filter_patched(self, sbom_csv):
        self.df_report = vulnxscan_reporting.filter_patched_report(
            self.df_report,
            sbom_csv,
            log=LOG,
        )

    def _apply_whitelist(self, whitelist_csv):
        vulnxscan_reporting.apply_whitelist_annotations(self.df_report, whitelist_csv)

    def _console_report(self):
        vulnxscan_reporting.render_console_report(
            self.df_report,
            df_triaged=self.df_triaged,
            log=LOG,
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
            LOG.verbose("Applying whitelist '%s'", args.whitelist)
            self._apply_whitelist(args.whitelist)
        if args.triage:
            LOG.verbose("Running vulnerability triage")
            self.df_triaged = triage_vulnerabilities(self.df_report, args.nixprs)
        # Rename 'version' to 'version_local'
        self.df_report.rename(columns={cols.VERSION: cols.VERSION_LOCAL}, inplace=True)

        LOG.debug("Writing reports")
        # Console report
        self._console_report()
        # File report
        vulnxscan_reporting.write_reports(
            self.df_report,
            args.out,
            df_triaged=self.df_triaged if args.triage else None,
        )
