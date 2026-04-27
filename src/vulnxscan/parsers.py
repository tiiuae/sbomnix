#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Parsing helpers for scanner output formats."""

import json

import numpy as np
import pandas as pd

from common.log import LOG, LOG_SPAM


def _severity_from_cache(cvss_cache, vuln_id):
    if cvss_cache is None:
        return ""
    return cvss_cache.get(vuln_id, "")


def parse_vulnix_json(json_str, *, cvss_cache=None, log=LOG):
    """Parse vulnix JSON output into a normalized dataframe."""
    vulnerable_packages = json.loads(json_str)
    vulnix_vulns_dict = {}
    setcol = vulnix_vulns_dict.setdefault
    for package in vulnerable_packages:
        cvss = package["cvssv3_basescore"]
        for cve in package["affected_by"]:
            severity = _severity_from_cache(cvss_cache, cve)
            if not severity and cve in cvss:
                severity = cvss[cve]
                if cvss_cache is not None:
                    cvss_cache[cve] = severity
            setcol("package", []).append(package["pname"])
            setcol("version", []).append(package["version"])
            setcol("vuln_id", []).append(cve)
            setcol("severity", []).append(severity)
            setcol("scanner", []).append("vulnix")
    df_vulnix = pd.DataFrame.from_dict(vulnix_vulns_dict)
    if not df_vulnix.empty:
        log.debug("Vulnix found vulnerabilities")
        df_vulnix.replace(np.nan, "", regex=True, inplace=True)
        df_vulnix.drop_duplicates(keep="first", inplace=True)
    return df_vulnix


def parse_grype_json(json_str, *, cvss_cache=None, log=LOG, log_spam=LOG_SPAM):
    """Parse grype JSON output into a normalized dataframe."""
    vulnerabilities = json.loads(json_str)
    log.log(log_spam, json.dumps(vulnerabilities, indent=2))
    grype_vulns_dict = {}
    setcol = grype_vulns_dict.setdefault
    for vuln in vulnerabilities["matches"]:
        if not vuln["artifact"]["version"]:
            log.log(
                log_spam,
                "'%s' missing version information: skipping",
                vuln["artifact"]["name"],
            )
            continue
        vid = vuln["vulnerability"]["id"]
        severity = _severity_from_cache(cvss_cache, vid)
        if not severity and vuln["vulnerability"]["cvss"]:
            for cvss in vuln["vulnerability"]["cvss"]:
                if float(cvss["version"]) >= 3:
                    log.log(log_spam, "selected cvss: %s", cvss)
                    severity = cvss["metrics"]["baseScore"]
                    if cvss_cache is not None:
                        cvss_cache[vid] = severity
                    break
        setcol("package", []).append(vuln["artifact"]["name"])
        setcol("version", []).append(vuln["artifact"]["version"])
        setcol("vuln_id", []).append(vuln["vulnerability"]["id"])
        setcol("severity", []).append(severity)
        setcol("scanner", []).append("grype")
    df_grype = pd.DataFrame.from_dict(grype_vulns_dict)
    if not df_grype.empty:
        log.debug("Grype found vulnerabilities")
        df_grype.replace(np.nan, "", regex=True, inplace=True)
        df_grype.drop_duplicates(keep="first", inplace=True)
    return df_grype


def normalize_osv_dataframe(df_osv, *, cvss_cache=None, log=LOG, log_spam=LOG_SPAM):
    """Normalize OSV query results into vulnxscan's dataframe shape."""
    if df_osv is None:
        return pd.DataFrame()
    df_osv = df_osv.copy(deep=True)
    if not df_osv.empty:
        df_osv["scanner"] = "osv"
        df_osv.replace(np.nan, "", regex=True, inplace=True)
        df_osv.drop_duplicates(keep="first", inplace=True)
        df_osv["modified"] = pd.to_datetime(
            df_osv["modified"],
            format="%Y-%m-%d",
            exact=False,
        )
        df_osv["severity"] = df_osv["vuln_id"].apply(
            lambda vuln_id: _severity_from_cache(cvss_cache, vuln_id)
        )
        log.log(log_spam, "osv data:\n%s", df_osv.to_markdown())
        log.debug("OSV scan found vulnerabilities")
    return df_osv
