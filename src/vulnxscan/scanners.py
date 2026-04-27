#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Scanner command execution helpers for vulnxscan."""

from common.log import LOG, LOG_VERBOSE
from common.proc import exec_cmd
from vulnxscan.osv_client import OSV


def run_vulnix_scan(target_path, buildtime=False, *, exec_cmd_fn=exec_cmd, log=LOG):
    """Run vulnix and return its process result."""
    log.log(LOG_VERBOSE, "Running vulnix scan")
    extra_opts = ["-C", "--json"]
    if buildtime:
        extra_opts = ["--json"]
    cmd = ["vulnix", target_path, *extra_opts]
    return exec_cmd_fn(
        cmd,
        raise_on_error=False,
        return_error=True,
        log_error=False,
    )


def run_grype_scan(sbom_path, *, exec_cmd_fn=exec_cmd, log=LOG):
    """Run grype against the given CycloneDX SBOM path."""
    log.log(LOG_VERBOSE, "Running grype scan")
    cmd = ["grype", f"sbom:{sbom_path}", "--add-cpes-if-none", "--output", "json"]
    return exec_cmd_fn(cmd)


def run_osv_scan(sbom_path, *, osv_factory=OSV, log=LOG):
    """Run OSV queries for the given CycloneDX SBOM path."""
    log.log(LOG_VERBOSE, "Running OSV scan")
    osv = osv_factory()
    osv.query_vulns(sbom_path)
    return osv.to_dataframe()
