#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CLI integration tests for sbomnix."""

import json
import shutil
import subprocess

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


def _nix(*args):
    cmd = ["nix", "--extra-experimental-features", "nix-command flakes", *args]
    return subprocess.run(cmd, capture_output=True, encoding="utf-8", check=True)


def _shared_output_flake(work_dir):
    """Write a flake exposing the two variants of test-shared-output.nix."""
    system = _nix("eval", "--impure", "--raw", "--expr", "builtins.currentSystem")
    flake_dir = work_dir / "shared-output-flake"
    flake_dir.mkdir()
    shutil.copy(RESOURCES_DIR / "test-shared-output.nix", flake_dir)
    (flake_dir / "flake.nix").write_text(
        "{ outputs = { self }: { packages."
        f'"{system.stdout}"'
        ' = import ./test-shared-output.nix { system = "'
        f"{system.stdout}"
        '"; }; }; }\n',
        encoding="utf-8",
    )
    return flake_dir.as_posix()


def _drv_closure(drv_path):
    requisites = _nix("path-info", "--recursive", drv_path).stdout.split()
    return {path for path in requisites if path.endswith(".drv")}


def test_sbomnix_runtime_derivations_follow_the_flakeref(
    _run_python_script, test_work_dir
):
    """Test runtime SBOMs name the target's own derivations.

    Both variants share one output path, so the store records only one of
    them as its deriver. Each SBOM must still name its own derivations,
    regardless of which variant was realised first.
    """
    flake = _shared_output_flake(test_work_dir)
    _nix("build", "--no-link", f"{flake}#a", f"{flake}#b")
    for name in ("a", "b"):
        drv_path = _nix("eval", "--raw", f"{flake}#{name}.drvPath").stdout
        out_path_cdx = test_work_dir / f"sbom_{name}_cdx.json"
        _run_python_script([SBOMNIX, f"{flake}#{name}", "--cdx", out_path_cdx])

        sbom = json.loads(out_path_cdx.read_text(encoding="utf-8"))
        assert sbom["metadata"]["component"]["bom-ref"] == drv_path
        bom_refs = {component["bom-ref"] for component in sbom["components"]}
        assert bom_refs == _drv_closure(drv_path) - {drv_path}


@pytest.mark.slow
def test_sbomnix_type_buildtime(_run_python_script, test_nix_drv, test_work_dir):
    """Test sbomnix generates valid CycloneDX json with buildtime dependencies."""
    out_path_cdx = test_work_dir / "sbom_cdx_test.json"
    out_path_spdx = test_work_dir / "sbom_spdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_drv,
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


@pytest.mark.slow
def test_sbomnix_depth(_run_python_script, test_nix_drv, test_work_dir):
    """Test sbomnix '--depth' option."""
    out_path_csv_1 = test_work_dir / "sbom_csv_test_1.csv"
    out_path_csv_2 = test_work_dir / "sbom_csv_test_2.csv"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_drv,
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
            test_nix_drv,
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
def test_compare_subsequent_cdx_sboms(_run_python_script, test_nix_drv, test_work_dir):
    """Compare two sbomnix runs with same target produce the same cdx sbom."""
    out_path_cdx_1 = test_work_dir / "sbom_cdx_test_1.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_drv,
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
            test_nix_drv,
            "--cdx",
            out_path_cdx_2.as_posix(),
            "--buildtime",
        ]
    )
    assert out_path_cdx_2.exists()

    _run_python_script([COMPARE_SBOMS, out_path_cdx_1, out_path_cdx_2])


@pytest.mark.slow
def test_compare_subsequent_spdx_sboms(_run_python_script, test_nix_drv, test_work_dir):
    """Compare two sbomnix runs with same target produce the same spdx sbom."""
    out_path_spdx_1 = test_work_dir / "sbom_spdx_test_1.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_drv,
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
            test_nix_drv,
            "--spdx",
            out_path_spdx_2.as_posix(),
            "--buildtime",
        ]
    )
    assert out_path_spdx_2.exists()

    _run_python_script([COMPARE_SBOMS, out_path_spdx_1, out_path_spdx_2])


@pytest.mark.slow
def test_compare_spdx_and_cdx_sboms(_run_python_script, test_nix_drv, test_work_dir):
    """Compare spdx and cdx sboms from the same sbomnix invocation."""
    out_path_spdx = test_work_dir / "sbom_spdx_test.json"
    out_path_cdx = test_work_dir / "sbom_cdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_drv,
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
