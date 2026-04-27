# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CycloneDX vulnerability enrichment helpers."""

import pathlib
from tempfile import NamedTemporaryFile

import pandas as pd

from common import columns as cols
from sbomnix.cdx import _vuln_to_cdx_vuln
from vulnxscan.vulnscan import VulnScan


def enrich_cdx_with_vulnerabilities(sbomdb, cdx):
    """Add vulnerability scan results to an existing CycloneDX document."""
    scanner = VulnScan()
    scanner.scan_vulnix(_vulnix_target_path(sbomdb), sbomdb.buildtime)
    temp_cdx_path = None
    try:
        with NamedTemporaryFile(
            delete=False,
            prefix="vulnxscan_",
            suffix=".json",
        ) as outfile:
            temp_cdx_path = outfile.name
            sbomdb.write_json(temp_cdx_path, cdx, printinfo=False)
        scanner.scan_grype(temp_cdx_path)
        scanner.scan_osv(temp_cdx_path)
    finally:
        if temp_cdx_path is not None:
            pathlib.Path(temp_cdx_path).unlink(missing_ok=True)

    cdx["vulnerabilities"] = []
    df_vulns = pd.concat(
        [scanner.df_grype, scanner.df_osv, scanner.df_vulnix],
        ignore_index=True,
    )
    if df_vulns.empty:
        return cdx
    if cols.MODIFIED in df_vulns.columns:
        df_vulns = df_vulns.drop(cols.MODIFIED, axis=1)
    vuln_grouped = df_vulns.groupby(
        [cols.PACKAGE, cols.VERSION, cols.SEVERITY, cols.VULN_ID],
        as_index=False,
    ).agg({cols.SCANNER: pd.Series.unique})
    vuln_components = pd.merge(
        left=vuln_grouped,
        right=sbomdb.df_sbomdb,
        how="inner",
        left_on=[cols.PACKAGE, cols.VERSION],
        right_on=[cols.PNAME, cols.VERSION],
    )
    for vuln in vuln_components.itertuples():
        cdx["vulnerabilities"].append(_vuln_to_cdx_vuln(vuln))
    return cdx


def _vulnix_target_path(sbomdb):
    """Return the target path to use for vulnix scans."""
    if sbomdb.buildtime:
        return sbomdb.target_deriver
    return sbomdb.nix_path
