#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CLI integration tests for vulnxscan."""

import pytest

from tests.testpaths import RESOURCES_DIR, VULNXSCAN


def test_vulnxscan_help(_run_python_script):
    """Test vulnxscan command line argument: '-h'."""
    _run_python_script([VULNXSCAN, "--help"])


@pytest.mark.network
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


@pytest.mark.network
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


@pytest.mark.network
def test_vulnxscan_triage_whitelist(_run_python_script, test_nix_result, test_work_dir):
    """Test vulnxscan scan with --triage and --whitelist."""
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
