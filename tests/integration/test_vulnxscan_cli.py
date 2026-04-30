#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CLI integration tests for vulnxscan."""

import pandas as pd
import pytest

from tests.testpaths import RESOURCES_DIR, VULNXSCAN

# Synthetic CVE committed in tests/resources/grype-test-db.tar.gz.
# It targets sbomnix-test-first==1.0, which is in the test derivation chain.
_SYNTHETIC_CVE = "CVE-TEST-2026-00001"


def test_vulnxscan_help(_run_python_script):
    """Test vulnxscan command line argument: '-h'."""
    _run_python_script([VULNXSCAN, "--help"])


@pytest.mark.network
@pytest.mark.grype
def test_vulnxscan_scan_nix_result(_run_python_script, test_nix_result, test_work_dir):
    """Test vulnxscan scan with the nix result as input."""
    out_path_vulns = test_work_dir / "vulnxscan_test.csv"
    _run_python_script(
        [
            VULNXSCAN,
            test_nix_result.as_posix(),
            "--out",
            out_path_vulns.as_posix(),
        ]
    )
    df = pd.read_csv(out_path_vulns)
    assert _SYNTHETIC_CVE in df["vuln_id"].values, (
        f"{_SYNTHETIC_CVE} not found in scan output — "
        "check grype-test-db.tar.gz matches the test fixture packages"
    )


@pytest.mark.network
@pytest.mark.grype
def test_vulnxscan_scan_sbom(_run_python_script, test_cdx_sbom, test_work_dir):
    """Test vulnxscan scan with SBOM as input."""
    out_path_vulns = test_work_dir / "vulnxscan_test.csv"
    _run_python_script(
        [
            VULNXSCAN,
            "--sbom",
            test_cdx_sbom.as_posix(),
            "--out",
            out_path_vulns.as_posix(),
        ]
    )


@pytest.mark.network
@pytest.mark.grype
def test_vulnxscan_triage(_run_python_script, test_nix_result, test_work_dir):
    """Test vulnxscan scan with --triage."""
    out_path_vulns = test_work_dir / "vulnxscan_test.csv"
    _run_python_script(
        [
            VULNXSCAN,
            "--triage",
            "--out",
            out_path_vulns.as_posix(),
            test_nix_result.as_posix(),
        ]
    )
    df = pd.read_csv(out_path_vulns)
    assert _SYNTHETIC_CVE in df["vuln_id"].values, (
        f"{_SYNTHETIC_CVE} not found in triage output"
    )


@pytest.mark.network
@pytest.mark.grype
def test_vulnxscan_triage_whitelist(_run_python_script, test_nix_result, test_work_dir):
    """Test vulnxscan scan with --triage and --whitelist."""
    # Positive case: CVE is present without --whitelist
    out_no_whitelist = test_work_dir / "vulnxscan_no_whitelist.csv"
    ret_no_wl = _run_python_script(
        [
            VULNXSCAN,
            "--triage",
            "--out",
            out_no_whitelist.as_posix(),
            test_nix_result.as_posix(),
        ],
        capture_output=True,
        text=True,
    )
    assert "Potential vulnerabilities impacting version_local" in ret_no_wl.stderr
    df_no_wl = pd.read_csv(out_no_whitelist)
    assert _SYNTHETIC_CVE in df_no_wl["vuln_id"].values

    # Suppressed case: CVE is whitelisted away
    out_path_vulns = test_work_dir / "vulnxscan_test.csv"
    whitelist_csv = RESOURCES_DIR / "whitelist_all.csv"
    assert whitelist_csv.exists()
    ret = _run_python_script(
        [
            VULNXSCAN,
            "--triage",
            "--whitelist",
            whitelist_csv.as_posix(),
            "--out",
            out_path_vulns.as_posix(),
            test_nix_result.as_posix(),
        ],
        capture_output=True,
        text=True,
    )
    assert "Potential vulnerabilities impacting version_local" not in ret.stderr
