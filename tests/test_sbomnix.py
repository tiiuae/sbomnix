#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name

""" Tests for sbomnix """

import os
import subprocess
import shutil
from pathlib import Path
import json
import imghdr
import pandas as pd
import jsonschema
import pytest

MYDIR = Path(os.path.dirname(os.path.realpath(__file__)))
TEST_WORK_DIR = MYDIR / "sbomnix_test_data"
TEST_NIX_RESULT = TEST_WORK_DIR / "result"
REPOROOT = MYDIR / ".."
SBOMNIX = MYDIR / ".." / "sbomnix" / "main.py"
NIXGRAPH = MYDIR / ".." / "nixgraph" / "main.py"
COMPARE_DEPS = MYDIR / "compare_deps.py"
COMPARE_SBOMS = MYDIR / "compare_sboms.py"


################################################################################


@pytest.fixture(autouse=True)
def set_up_test_data():
    """Fixture to set up the test data"""
    print("setup")
    shutil.rmtree(TEST_WORK_DIR, ignore_errors=True)
    TEST_WORK_DIR.mkdir(parents=True, exist_ok=True)
    # Build nixpkgs.hello, output symlink to TEST_NIX_RESULT
    # (assumes nix-build is available in $PATH)
    cmd = ["nix-build", "<nixpkgs>", "-A", "hello", "-o", TEST_NIX_RESULT]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert Path(TEST_NIX_RESULT).exists()
    os.chdir(TEST_WORK_DIR)
    yield "resource"
    print("clean up")
    shutil.rmtree(TEST_WORK_DIR)


################################################################################


def test_nix_shell():
    """Test nix-shell doesn't fail and enters venv"""
    # Test running nix-shell. Inside the shell, test that
    # VIRTUAL_ENV variable is set, exit with failure if it is not set:
    run_cmd = "if [ -z ${VIRTUAL_ENV+x} ]; then exit 1; else exit 0; fi"
    cmd = ["nix-shell", "--run", run_cmd]
    os.chdir(REPOROOT)
    assert subprocess.run(cmd, check=True).returncode == 0
    os.chdir(TEST_WORK_DIR)


################################################################################


def test_sbomnix_help():
    """Test sbomnix command line argument: '-h'"""
    cmd = [SBOMNIX, "-h"]
    assert subprocess.run(cmd, check=True).returncode == 0


def test_sbomnix_help_flake():
    """Test sbomnix command line argument: '-h' running sbomnix as flake"""
    cmd = ["nix", "run", f"{REPOROOT}#sbomnix", "--", "-h"]
    assert subprocess.run(cmd, check=True).returncode == 0


def test_sbomnix_type_runtime():
    """Test sbomnix '--type=runtime' generates valid CycloneDX json"""
    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    out_path_spdx = TEST_WORK_DIR / "sbom_spdx_test.json"
    cmd = [
        SBOMNIX,
        TEST_NIX_RESULT,
        "--cdx",
        out_path_cdx.as_posix(),
        "--spdx",
        out_path_spdx.as_posix(),
        "--type",
        "runtime",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_cdx.exists()
    assert out_path_spdx.exists()
    cdx_schema_path = MYDIR / "resources" / "cdx_bom-1.3.schema.json"
    assert cdx_schema_path.exists()
    validate_json(out_path_cdx.as_posix(), cdx_schema_path)
    spdx_schema_path = MYDIR / "resources" / "spdx_bom-2.3.schema.json"
    assert spdx_schema_path.exists()
    validate_json(out_path_spdx.as_posix(), spdx_schema_path)


def test_sbomnix_type_buildtime():
    """Test sbomnix '--type=runtime' generates valid CycloneDX json"""
    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    out_path_spdx = TEST_WORK_DIR / "sbom_spdx_test.json"
    cmd = [
        SBOMNIX,
        TEST_NIX_RESULT,
        "--cdx",
        out_path_cdx.as_posix(),
        "--spdx",
        out_path_spdx.as_posix(),
        "--type",
        "buildtime",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_cdx.exists()
    assert out_path_spdx.exists()
    cdx_schema_path = MYDIR / "resources" / "cdx_bom-1.3.schema.json"
    assert cdx_schema_path.exists()
    validate_json(out_path_cdx.as_posix(), cdx_schema_path)
    spdx_schema_path = MYDIR / "resources" / "spdx_bom-2.3.schema.json"
    assert spdx_schema_path.exists()
    validate_json(out_path_spdx.as_posix(), spdx_schema_path)


def test_sbomnix_cdx_type_both():
    """Test sbomnix '--type=both' generates valid CycloneDX json"""
    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    out_path_spdx = TEST_WORK_DIR / "sbom_spdx_test.json"
    cmd = [
        SBOMNIX,
        TEST_NIX_RESULT,
        "--cdx",
        out_path_cdx.as_posix(),
        "--spdx",
        out_path_spdx.as_posix(),
        "--type",
        "both",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_cdx.exists()
    assert out_path_spdx.exists()
    cdx_schema_path = MYDIR / "resources" / "cdx_bom-1.3.schema.json"
    assert cdx_schema_path.exists()
    validate_json(out_path_cdx.as_posix(), cdx_schema_path)
    spdx_schema_path = MYDIR / "resources" / "spdx_bom-2.3.schema.json"
    assert spdx_schema_path.exists()
    validate_json(out_path_spdx.as_posix(), spdx_schema_path)


################################################################################


def test_nixgraph_help():
    """Test nixgraph command line argument: '-h'"""
    cmd = [NIXGRAPH, "-h"]
    assert subprocess.run(cmd, check=True).returncode == 0


def test_nixgraph_help_flake():
    """Test nixgraph command line argument: '-h' running nixgraph as flake"""
    cmd = ["nix", "run", f"{REPOROOT}#nixgraph", "--", "-h"]
    assert subprocess.run(cmd, check=True).returncode == 0


def test_nixgraph_png():
    """Test nixgraph with png output generates valid png image"""
    png_out = TEST_WORK_DIR / "graph.png"
    cmd = [NIXGRAPH, TEST_NIX_RESULT, "--out", png_out, "--depth", "3"]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert Path(png_out).exists()
    # Check the output is valid png file
    assert imghdr.what(png_out) == "png"


def test_nixgraph_csv():
    """Test nixgraph with csv output generates valid csv"""
    csv_out = TEST_WORK_DIR / "graph.csv"
    cmd = [NIXGRAPH, TEST_NIX_RESULT, "--out", csv_out, "--depth", "3"]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert Path(csv_out).exists()
    # Check the output is valid csv file
    df_out = pd.read_csv(csv_out)
    assert not df_out.empty


def test_nixgraph_csv_buildtime():
    """Test nixgraph with buildtime csv output generates valid csv"""
    csv_out = TEST_WORK_DIR / "graph_buildtime.csv"
    cmd = [NIXGRAPH, TEST_NIX_RESULT, "--out", csv_out, "--buildtime"]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert Path(csv_out).exists()
    # Check the output is valid csv file
    df_out = pd.read_csv(csv_out)
    assert not df_out.empty


def test_nixgraph_csv_graph_inverse():
    """Test nixgraph with '--inverse' argument"""
    csv_out = TEST_WORK_DIR / "graph.csv"
    cmd = [
        NIXGRAPH,
        TEST_NIX_RESULT,
        "--out",
        csv_out,
        "--depth=100",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert Path(csv_out).exists()
    df_out = pd.read_csv(csv_out)
    assert not df_out.empty

    csv_out_inv = TEST_WORK_DIR / "graph_inverse.csv"
    cmd = [
        NIXGRAPH,
        TEST_NIX_RESULT,
        "--out",
        csv_out_inv,
        "--depth=100",
        "--inverse=libunistring",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert Path(csv_out_inv).exists()
    df_out_inv = pd.read_csv(csv_out_inv)
    assert not df_out_inv.empty

    # When 'depth' covers the entire graph, the output from
    # the two above commands should be the same, except for column
    # 'graph_depth': below, we remove that column from both outputs and
    # compare the two dataframes

    df_out = df_out.drop("graph_depth", axis=1)
    df_out = df_out.sort_values(by=["src_path"])

    df_out_inv = df_out_inv.drop("graph_depth", axis=1)
    df_out_inv = df_out_inv.sort_values(by=["src_path"])

    df_diff = df_difference(df_out, df_out_inv)
    assert df_diff.empty, df_to_string(df_diff)


################################################################################


def test_compare_deps_runtime():
    """Compare nixgraph vs sbom runtime dependencies"""
    graph_csv_out = TEST_WORK_DIR / "graph.csv"
    cmd = [
        NIXGRAPH,
        TEST_NIX_RESULT,
        "--out",
        graph_csv_out,
        "--depth=100",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert Path(graph_csv_out).exists()

    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    cmd = [
        SBOMNIX,
        TEST_NIX_RESULT,
        "--cdx",
        out_path_cdx.as_posix(),
        "--type",
        "runtime",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_cdx.exists()

    cmd = [
        COMPARE_DEPS,
        "--sbom",
        out_path_cdx,
        "--graph",
        graph_csv_out,
    ]
    assert subprocess.run(cmd, check=True).returncode == 0


def test_compare_deps_buildtime():
    """Compare nixgraph vs sbom buildtime dependencies"""
    graph_csv_out = TEST_WORK_DIR / "graph.csv"
    cmd = [
        NIXGRAPH,
        TEST_NIX_RESULT,
        "--out",
        graph_csv_out,
        "--depth=100",
        "--buildtime",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert Path(graph_csv_out).exists()

    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    cmd = [
        SBOMNIX,
        TEST_NIX_RESULT,
        "--cdx",
        out_path_cdx.as_posix(),
        "--type",
        "buildtime",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_cdx.exists()

    cmd = [
        COMPARE_DEPS,
        "--sbom",
        out_path_cdx,
        "--graph",
        graph_csv_out,
    ]
    assert subprocess.run(cmd, check=True).returncode == 0


def test_compare_subsequent_cdx_sboms():
    """Compare two sbomnix runs with same target produce the same cdx sbom"""
    out_path_cdx_1 = TEST_WORK_DIR / "sbom_cdx_test_1.json"
    cmd = [
        SBOMNIX,
        TEST_NIX_RESULT,
        "--cdx",
        out_path_cdx_1.as_posix(),
        "--type",
        "both",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_cdx_1.exists()

    out_path_cdx_2 = TEST_WORK_DIR / "sbom_cdx_test_2.json"
    cmd = [
        SBOMNIX,
        TEST_NIX_RESULT,
        "--cdx",
        out_path_cdx_2.as_posix(),
        "--type",
        "both",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_cdx_2.exists()

    cmd = [
        COMPARE_SBOMS,
        out_path_cdx_1,
        out_path_cdx_2,
    ]
    assert subprocess.run(cmd, check=True).returncode == 0


def test_compare_subsequent_spdx_sboms():
    """Compare two sbomnix runs with same target produce the same spdx sbom"""
    out_path_spdx_1 = TEST_WORK_DIR / "sbom_spdx_test_1.json"
    cmd = [
        SBOMNIX,
        TEST_NIX_RESULT,
        "--spdx",
        out_path_spdx_1.as_posix(),
        "--type",
        "both",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_spdx_1.exists()

    out_path_spdx_2 = TEST_WORK_DIR / "sbom_spdx_test_2.json"
    cmd = [
        SBOMNIX,
        TEST_NIX_RESULT,
        "--spdx",
        out_path_spdx_2.as_posix(),
        "--type",
        "both",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_spdx_2.exists()

    cmd = [
        COMPARE_SBOMS,
        out_path_spdx_1,
        out_path_spdx_2,
    ]
    assert subprocess.run(cmd, check=True).returncode == 0


def test_compare_spdx_and_cdx_sboms():
    """Compare spdx and cdx sboms from the same sbomnix invocation"""
    out_path_spdx = TEST_WORK_DIR / "sbom_spdx_test.json"
    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    cmd = [
        SBOMNIX,
        TEST_NIX_RESULT,
        "--cdx",
        out_path_cdx.as_posix(),
        "--spdx",
        out_path_spdx.as_posix(),
        "--type",
        "both",
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_cdx.exists()
    assert out_path_spdx.exists()

    cmd = [
        COMPARE_SBOMS,
        out_path_cdx,
        out_path_spdx,
    ]
    assert subprocess.run(cmd, check=True).returncode == 0


################################################################################


def test_vulnxscan_help_flake():
    """Test vulnxscan command line argument: '-h' running vulnxscan as flake"""
    cmd = ["nix", "run", f"{REPOROOT}#vulnxscan", "--", "-h"]
    assert subprocess.run(cmd, check=True).returncode == 0


@pytest.mark.skip_in_ci
def test_vulnxscan_scan_nix_result():
    """Test vulnxscan scan with TEST_NIX_RESULT as input"""
    cmd = [
        "nix",
        "run",
        f"{REPOROOT}#vulnxscan",
        "--",
        TEST_NIX_RESULT.as_posix(),
    ]
    assert subprocess.run(cmd, check=True).returncode == 0


@pytest.mark.skip_in_ci
def test_vulnxscan_scan_sbom():
    """Test vulnxscan scan with SBOM as input"""
    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    cmd = [
        "nix",
        "run",
        f"{REPOROOT}#sbomnix",
        "--",
        TEST_NIX_RESULT,
        "--cdx",
        out_path_cdx,
    ]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_cdx.exists()

    cmd = [
        "nix",
        "run",
        f"{REPOROOT}#vulnxscan",
        "--",
        "--sbom",
        out_path_cdx.as_posix(),
    ]
    assert subprocess.run(cmd, check=True).returncode == 0


################################################################################


def validate_json(file_path, schema_path):
    """Validate json file matches schema"""
    with open(file_path, encoding="utf-8") as json_file, open(
        schema_path, encoding="utf-8"
    ) as schema_file:
        json_obj = json.load(json_file)
        schema_obj = json.load(schema_file)
        jsonschema.validate(json_obj, schema_obj)


def df_to_string(df):
    """Convert dataframe to string"""
    return (
        "\n"
        + df.to_string(max_rows=None, max_cols=None, index=False, justify="left")
        + "\n"
    )


def df_difference(df_left, df_right):
    """Return dataframe that represents diff of two dataframes"""
    df_right = df_right.astype(df_left.dtypes.to_dict())
    df = df_left.merge(
        df_right,
        how="outer",
        indicator=True,
    )
    # Keep only the rows that differ (that are not in both)
    df = df[df["_merge"] != "both"]
    # Rename 'left_only' and 'right_only' values in '_merge' column
    df["_merge"] = df["_merge"].replace(["left_only"], "EXPECTED ==>  ")
    df["_merge"] = df["_merge"].replace(["right_only"], "RESULT ==>  ")
    # Re-order columns: last column ('_merge') becomes first
    cols = df.columns.tolist()
    cols = cols[-1:] + cols[:-1]
    df = df[cols]
    # Rename '_merge' column to empty string
    df = df.rename(columns={"_merge": ""})
    return df


################################################################################


if __name__ == "__main__":
    pytest.main([__file__])


################################################################################
