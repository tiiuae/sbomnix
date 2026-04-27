#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CLI integration tests for sbomnix."""

import pandas as pd
import pytest

from tests.testpaths import COMPARE_SBOMS, RESOURCES_DIR, SBOMNIX
from tests.testutils import df_difference, df_to_string, validate_json


def test_sbomnix_help(_run_python_script):
    """Test sbomnix command line argument: '-h'."""
    _run_python_script([SBOMNIX, "-h"])


def test_sbomnix_type_runtime(_run_python_script, test_nix_result, test_work_dir):
    """Test sbomnix generates valid CycloneDX json with runtime dependencies."""
    out_path_cdx = test_work_dir / "sbom_cdx_test.json"
    out_path_spdx = test_work_dir / "sbom_spdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_result,
            "--cdx",
            out_path_cdx.as_posix(),
            "--spdx",
            out_path_spdx.as_posix(),
        ]
    )
    assert out_path_cdx.exists()
    assert out_path_spdx.exists()

    cdx_schema_path = RESOURCES_DIR / "cdx_bom-1.4.schema.json"
    assert cdx_schema_path.exists()
    validate_json(out_path_cdx.as_posix(), cdx_schema_path)

    spdx_schema_path = RESOURCES_DIR / "spdx_bom-2.3.schema.json"
    assert spdx_schema_path.exists()
    validate_json(out_path_spdx.as_posix(), spdx_schema_path)


@pytest.mark.slow
def test_sbomnix_type_buildtime(_run_python_script, test_nix_result, test_work_dir):
    """Test sbomnix generates valid CycloneDX json with buildtime dependencies."""
    out_path_cdx = test_work_dir / "sbom_cdx_test.json"
    out_path_spdx = test_work_dir / "sbom_spdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_result,
            "--cdx",
            out_path_cdx.as_posix(),
            "--spdx",
            out_path_spdx.as_posix(),
            "--buildtime",
        ]
    )
    assert out_path_cdx.exists()
    assert out_path_spdx.exists()

    cdx_schema_path = RESOURCES_DIR / "cdx_bom-1.4.schema.json"
    assert cdx_schema_path.exists()
    validate_json(out_path_cdx.as_posix(), cdx_schema_path)

    spdx_schema_path = RESOURCES_DIR / "spdx_bom-2.3.schema.json"
    assert spdx_schema_path.exists()
    validate_json(out_path_spdx.as_posix(), spdx_schema_path)


def test_sbomnix_depth(_run_python_script, test_nix_result, test_work_dir):
    """Test sbomnix '--depth' option."""
    out_path_csv_1 = test_work_dir / "sbom_csv_test_1.csv"
    out_path_csv_2 = test_work_dir / "sbom_csv_test_2.csv"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_result,
            "--buildtime",
            "--csv",
            out_path_csv_1.as_posix(),
            "--depth=2",
        ]
    )
    assert out_path_csv_1.exists()
    df_out_1 = pd.read_csv(out_path_csv_1)
    assert not df_out_1.empty

    _run_python_script(
        [
            SBOMNIX,
            test_nix_result,
            "--buildtime",
            "--csv",
            out_path_csv_2.as_posix(),
            "--depth=1",
        ]
    )
    assert out_path_csv_2.exists()
    df_out_2 = pd.read_csv(out_path_csv_2)
    assert not df_out_2.empty

    df_diff = df_difference(df_out_1, df_out_2)
    assert not df_diff.empty, df_to_string(df_diff)
    df_right_only = df_diff[df_diff["_merge"] == "right_only"]
    assert df_right_only.empty, df_to_string(df_diff)


@pytest.mark.slow
def test_compare_subsequent_cdx_sboms(
    _run_python_script, test_nix_result, test_work_dir
):
    """Compare two sbomnix runs with same target produce the same cdx sbom."""
    out_path_cdx_1 = test_work_dir / "sbom_cdx_test_1.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_result,
            "--cdx",
            out_path_cdx_1.as_posix(),
            "--buildtime",
        ]
    )
    assert out_path_cdx_1.exists()

    out_path_cdx_2 = test_work_dir / "sbom_cdx_test_2.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_result,
            "--cdx",
            out_path_cdx_2.as_posix(),
            "--buildtime",
        ]
    )
    assert out_path_cdx_2.exists()

    _run_python_script([COMPARE_SBOMS, out_path_cdx_1, out_path_cdx_2])


@pytest.mark.slow
def test_compare_subsequent_spdx_sboms(
    _run_python_script, test_nix_result, test_work_dir
):
    """Compare two sbomnix runs with same target produce the same spdx sbom."""
    out_path_spdx_1 = test_work_dir / "sbom_spdx_test_1.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_result,
            "--spdx",
            out_path_spdx_1.as_posix(),
            "--buildtime",
        ]
    )
    assert out_path_spdx_1.exists()

    out_path_spdx_2 = test_work_dir / "sbom_spdx_test_2.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_result,
            "--spdx",
            out_path_spdx_2.as_posix(),
            "--buildtime",
        ]
    )
    assert out_path_spdx_2.exists()

    _run_python_script([COMPARE_SBOMS, out_path_spdx_1, out_path_spdx_2])


@pytest.mark.slow
def test_compare_spdx_and_cdx_sboms(_run_python_script, test_nix_result, test_work_dir):
    """Compare spdx and cdx sboms from the same sbomnix invocation."""
    out_path_spdx = test_work_dir / "sbom_spdx_test.json"
    out_path_cdx = test_work_dir / "sbom_cdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_result,
            "--cdx",
            out_path_cdx.as_posix(),
            "--spdx",
            out_path_spdx.as_posix(),
            "--buildtime",
        ]
    )
    assert out_path_cdx.exists()
    assert out_path_spdx.exists()

    _run_python_script([COMPARE_SBOMS, out_path_cdx, out_path_spdx])
