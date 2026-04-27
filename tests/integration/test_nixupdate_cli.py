#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CLI integration tests for nix_outdated."""

import pytest

from tests.testpaths import NIX_OUTDATED


def test_nix_outdated_help(_run_python_script):
    """Test nix_outdated command line argument: '-h'."""
    _run_python_script([NIX_OUTDATED, "-h"])


@pytest.mark.network
@pytest.mark.slow
def test_nix_outdated_result(
    _run_python_script_retry_on_repology_network_error, test_nix_result, test_work_dir
):
    """Test nix_outdated with the nix result as input."""
    out_path_nix_outdated = test_work_dir / "nix_outdated.csv"
    _run_python_script_retry_on_repology_network_error(
        [
            NIX_OUTDATED,
            "--out",
            out_path_nix_outdated.as_posix(),
            test_nix_result,
        ]
    )
    assert out_path_nix_outdated.exists()
