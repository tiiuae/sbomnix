#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CLI integration tests for repology."""

import pytest

from tests.testpaths import REPOLOGY_CLI, SBOMNIX


def test_repology_cli_help(_run_python_script):
    """Test repology_cli command line argument: '-h'."""
    _run_python_script([REPOLOGY_CLI, "-h"])


@pytest.mark.network
@pytest.mark.slow
def test_repology_cli_sbom(
    _run_python_script,
    _run_python_script_retry_on_repology_network_error,
    test_nix_result,
    test_work_dir,
):
    """Test repology_cli with SBOM as input."""
    out_path_cdx = test_work_dir / "sbom_cdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_result,
            "--cdx",
            out_path_cdx,
        ]
    )
    assert out_path_cdx.exists()

    out_path_repology = test_work_dir / "repology.csv"
    _run_python_script_retry_on_repology_network_error(
        [
            REPOLOGY_CLI,
            "--sbom_cdx",
            out_path_cdx.as_posix(),
            "--repository",
            "nix_unstable",
            "--out",
            out_path_repology.as_posix(),
        ]
    )
    assert out_path_repology.exists()
