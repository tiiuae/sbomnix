#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name, global-statement, redefined-outer-name

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

from sbomnix.utils import (
    df_from_csv_file,
)

from scripts.vulnxscan.vulnxscan import (
    load_whitelist,
    df_apply_whitelist,
)


MYDIR = Path(os.path.dirname(os.path.realpath(__file__)))

# These two tools are executed as scripts from this file,
# but don't contain any tests themselves
COMPARE_DEPS = MYDIR / "compare_deps.py"
COMPARE_SBOMS = MYDIR / "compare_sboms.py"

REPOROOT = MYDIR / ".."

# The different entrypoints of the application. Currently we invoke them with a
# new python interpreter, as it's not in a shape yet to import a function we
# pass arguments to.
SBOMNIX = REPOROOT / "sbomnix" / "main.py"
NIXGRAPH = REPOROOT / "nixgraph" / "main.py"
NIX_OUTDATED = REPOROOT / "scripts" / "nixupdate" / "nix_outdated.py"
VULNXSCAN = REPOROOT / "scripts" / "vulnxscan" / "vulnxscan.py"
REPOLOGY_CLI = REPOROOT / "scripts" / "repology" / "repology_cli.py"
REPOLOGY_CVE = REPOROOT / "scripts" / "repology" / "repology_cve.py"

TEST_WORK_DIR = None
TEST_NIX_RESULT = None

################################################################################


@pytest.fixture(scope="session")
def test_work_dir(tmp_path_factory):
    """Fixture for session-scope tempdir"""
    tempdir = tmp_path_factory.mktemp("testdata")
    return Path(tempdir)


@pytest.fixture(autouse=True)
def set_up_test_data(test_work_dir):
    """Fixture to set up the test data"""
    print("setup")
    global TEST_WORK_DIR
    TEST_WORK_DIR = test_work_dir
    print(f"using TEST_WORK_DIR: {TEST_WORK_DIR}")
    global TEST_NIX_RESULT
    TEST_NIX_RESULT = TEST_WORK_DIR / "result"
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


def _run_python_script(args, **kwargs):
    """small helper function invoking the python script and args, ensuring 0 return code

    This also sets PYTHONPATH to the repo root, so these scripts can import
    sbomnix or scripts on their own.
    """
    # copy, so we don't mutate env for this process, only for the spawned one.
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{env['PYTHONPATH']}:{REPOROOT}"
    return subprocess.run(args, **kwargs, check=True, env=env)


def test_sbomnix_help():
    """Test sbomnix command line argument: '-h'"""
    _run_python_script([SBOMNIX, "-h"])


def test_sbomnix_type_runtime():
    """Test sbomnix '--type=runtime' generates valid CycloneDX json"""
    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    out_path_spdx = TEST_WORK_DIR / "sbom_spdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--cdx",
            out_path_cdx.as_posix(),
            "--spdx",
            out_path_spdx.as_posix(),
            "--type",
            "runtime",
        ]
    )
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
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--cdx",
            out_path_cdx.as_posix(),
            "--spdx",
            out_path_spdx.as_posix(),
            "--type",
            "buildtime",
        ]
    )
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
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--cdx",
            out_path_cdx.as_posix(),
            "--spdx",
            out_path_spdx.as_posix(),
            "--type",
            "both",
        ]
    )
    assert out_path_cdx.exists()
    assert out_path_spdx.exists()
    cdx_schema_path = MYDIR / "resources" / "cdx_bom-1.3.schema.json"
    assert cdx_schema_path.exists()
    validate_json(out_path_cdx.as_posix(), cdx_schema_path)
    spdx_schema_path = MYDIR / "resources" / "spdx_bom-2.3.schema.json"
    assert spdx_schema_path.exists()
    validate_json(out_path_spdx.as_posix(), spdx_schema_path)


def test_sbomnix_depth():
    """Test sbomnix '--depth' option"""
    out_path_csv_1 = TEST_WORK_DIR / "sbom_csv_test_1.csv"
    out_path_csv_2 = TEST_WORK_DIR / "sbom_csv_test_2.csv"
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--csv",
            out_path_csv_1.as_posix(),
            "--type",
            "runtime",
        ]
    )
    assert out_path_csv_1.exists()
    df_out_1 = pd.read_csv(out_path_csv_1)
    assert not df_out_1.empty

    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--csv",
            out_path_csv_2.as_posix(),
            "--type",
            "runtime",
            "--depth=1",
        ]
    )
    assert out_path_csv_2.exists()
    df_out_2 = pd.read_csv(out_path_csv_2)
    assert not df_out_2.empty
    # Check the dataframes are not equal
    df_diff = df_difference(df_out_1, df_out_2)
    assert not df_diff.empty, df_to_string(df_diff)
    df_right_only = df_diff[df_diff["_merge"] == "right_only"]
    # Check df_out_1 contains rows that are not in df_out_2
    assert df_right_only.empty, df_to_string(df_diff)


################################################################################


def test_nixgraph_help():
    """Test nixgraph command line argument: '-h'"""
    _run_python_script([NIXGRAPH, "-h"])


def test_nixgraph_png():
    """Test nixgraph with png output generates valid png image"""
    png_out = TEST_WORK_DIR / "graph.png"
    _run_python_script([NIXGRAPH, TEST_NIX_RESULT, "--out", png_out, "--depth", "3"])
    assert Path(png_out).exists()
    # Check the output is valid png file
    assert imghdr.what(png_out) == "png"


def test_nixgraph_csv():
    """Test nixgraph with csv output generates valid csv"""
    csv_out = TEST_WORK_DIR / "graph.csv"
    _run_python_script([NIXGRAPH, TEST_NIX_RESULT, "--out", csv_out, "--depth", "3"])
    assert Path(csv_out).exists()
    # Check the output is valid csv file
    df_out = pd.read_csv(csv_out)
    assert not df_out.empty


def test_nixgraph_csv_buildtime():
    """Test nixgraph with buildtime csv output generates valid csv"""
    csv_out = TEST_WORK_DIR / "graph_buildtime.csv"
    _run_python_script([NIXGRAPH, TEST_NIX_RESULT, "--out", csv_out, "--buildtime"])
    assert Path(csv_out).exists()
    # Check the output is valid csv file
    df_out = pd.read_csv(csv_out)
    assert not df_out.empty


def test_nixgraph_csv_graph_inverse():
    """Test nixgraph with '--inverse' argument"""
    csv_out = TEST_WORK_DIR / "graph.csv"
    _run_python_script(
        [
            NIXGRAPH,
            TEST_NIX_RESULT,
            "--out",
            csv_out,
            "--depth=100",
        ]
    )
    assert Path(csv_out).exists()
    df_out = pd.read_csv(csv_out)
    assert not df_out.empty

    csv_out_inv = TEST_WORK_DIR / "graph_inverse.csv"
    _run_python_script(
        [
            NIXGRAPH,
            TEST_NIX_RESULT,
            "--out",
            csv_out_inv,
            "--depth=100",
            "--inverse=.*",
        ]
    )
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
    _run_python_script(
        [
            NIXGRAPH,
            TEST_NIX_RESULT,
            "--out",
            graph_csv_out,
            "--depth=100",
        ]
    )
    assert Path(graph_csv_out).exists()

    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--cdx",
            out_path_cdx.as_posix(),
            "--type",
            "runtime",
        ]
    )
    assert out_path_cdx.exists()

    _run_python_script(
        [
            COMPARE_DEPS,
            "--sbom",
            out_path_cdx,
            "--graph",
            graph_csv_out,
        ]
    )


def test_compare_deps_buildtime():
    """Compare nixgraph vs sbom buildtime dependencies"""
    graph_csv_out = TEST_WORK_DIR / "graph.csv"
    _run_python_script(
        [
            NIXGRAPH,
            TEST_NIX_RESULT,
            "--out",
            graph_csv_out,
            "--depth=100",
            "--buildtime",
        ]
    )
    assert Path(graph_csv_out).exists()

    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--cdx",
            out_path_cdx.as_posix(),
            "--type",
            "buildtime",
        ]
    )
    assert out_path_cdx.exists()

    _run_python_script(
        [
            COMPARE_DEPS,
            "--sbom",
            out_path_cdx,
            "--graph",
            graph_csv_out,
        ]
    )


def test_compare_subsequent_cdx_sboms():
    """Compare two sbomnix runs with same target produce the same cdx sbom"""
    out_path_cdx_1 = TEST_WORK_DIR / "sbom_cdx_test_1.json"
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--cdx",
            out_path_cdx_1.as_posix(),
            "--type",
            "both",
        ]
    )
    assert out_path_cdx_1.exists()

    out_path_cdx_2 = TEST_WORK_DIR / "sbom_cdx_test_2.json"
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--cdx",
            out_path_cdx_2.as_posix(),
            "--type",
            "both",
        ]
    )
    assert out_path_cdx_2.exists()

    _run_python_script(
        [
            COMPARE_SBOMS,
            out_path_cdx_1,
            out_path_cdx_2,
        ]
    )


def test_compare_subsequent_spdx_sboms():
    """Compare two sbomnix runs with same target produce the same spdx sbom"""
    out_path_spdx_1 = TEST_WORK_DIR / "sbom_spdx_test_1.json"
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--spdx",
            out_path_spdx_1.as_posix(),
            "--type",
            "both",
        ]
    )
    assert out_path_spdx_1.exists()

    out_path_spdx_2 = TEST_WORK_DIR / "sbom_spdx_test_2.json"
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--spdx",
            out_path_spdx_2.as_posix(),
            "--type",
            "both",
        ]
    )
    assert out_path_spdx_2.exists()

    _run_python_script(
        [
            COMPARE_SBOMS,
            out_path_spdx_1,
            out_path_spdx_2,
        ]
    )


def test_compare_spdx_and_cdx_sboms():
    """Compare spdx and cdx sboms from the same sbomnix invocation"""
    out_path_spdx = TEST_WORK_DIR / "sbom_spdx_test.json"
    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--cdx",
            out_path_cdx.as_posix(),
            "--spdx",
            out_path_spdx.as_posix(),
            "--type",
            "both",
        ]
    )
    assert out_path_cdx.exists()
    assert out_path_spdx.exists()

    _run_python_script(
        [
            COMPARE_SBOMS,
            out_path_cdx,
            out_path_spdx,
        ]
    )


################################################################################


def test_vulnxscan_help():
    """Test vulnxscan command line argument: '-h'"""
    _run_python_script([VULNXSCAN, "--help"])


@pytest.mark.skip_in_ci
def test_vulnxscan_scan_nix_result():
    """Test vulnxscan scan with TEST_NIX_RESULT as input"""
    out_path_vulns = TEST_WORK_DIR / "vulnxscan_test.csv"
    _run_python_script(
        [
            VULNXSCAN,
            TEST_NIX_RESULT.as_posix(),
            "--out",
            out_path_vulns.as_posix(),
        ]
    )


@pytest.mark.skip_in_ci
def test_vulnxscan_scan_sbom():
    """Test vulnxscan scan with SBOM as input"""
    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--cdx",
            out_path_cdx,
        ]
    )
    assert out_path_cdx.exists()

    out_path_vulns = TEST_WORK_DIR / "vulnxscan_test.csv"
    _run_python_script(
        [
            VULNXSCAN,
            "--sbom",
            out_path_cdx.as_posix(),
            "--out",
            out_path_vulns.as_posix(),
        ]
    )


@pytest.mark.skip
# vulnxscan --triage assumes repology_cli in $PATH.
# FUTUREWORK: expose this as library code?
def test_vulnxscan_triage():
    """Test vulnxscan scan with --triage"""
    out_path_vulns = TEST_WORK_DIR / "vulnxscan_test.csv"
    _run_python_script(
        [
            VULNXSCAN,
            "--triage",
            "--out",
            out_path_vulns.as_posix(),
            TEST_NIX_RESULT.as_posix(),
        ]
    )


@pytest.mark.skip
# vulnxscan --triage assumes repology_cli in $PATH.
# FUTUREWORK: expose this as library code?
def test_vulnxscan_triage_whitelist():
    """Test vulnxscan scan with --triage and --whitelist"""
    out_path_vulns = TEST_WORK_DIR / "vulnxscan_test.csv"
    whitelist_csv = MYDIR / "resources" / "whitelist_all.csv"
    assert whitelist_csv.exists()
    ret = _run_python_script(
        [
            VULNXSCAN,
            "--triage",
            "--whitelist",
            whitelist_csv.as_posix(),
            "--out",
            out_path_vulns.as_posix(),
            TEST_NIX_RESULT.as_posix(),
        ],
        capture_output=True,
        text=True,
    )
    # Console output should not include any vulnerabilities
    # when whitelisting all vulnerabilities
    assert "Potential vulnerabilities impacting version_local" not in ret.stderr


################################################################################


def test_repology_cli_help():
    """
    Test repology_cli command line argument: '-h'
    """
    _run_python_script([REPOLOGY_CLI, "-h"])


def test_repology_cli_sbom():
    """Test repology_cli with SBOM as input"""
    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            TEST_NIX_RESULT,
            "--cdx",
            out_path_cdx,
        ]
    )
    assert out_path_cdx.exists()

    out_path_repology = TEST_WORK_DIR / "repology.csv"
    _run_python_script(
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


################################################################################


def test_nix_outdated_help():
    """
    Test nix_outdated command line argument: '-h'
    """
    _run_python_script([NIX_OUTDATED, "-h"])


@pytest.mark.skip
# vulnxscan --triage assumes repology_cli in $PATH.
# FUTUREWORK: expose this as library code?
def test_nix_outdated_result():
    """Test nix_outdated with TEST_NIX_RESULT as input"""
    out_path_nix_outdated = TEST_WORK_DIR / "nix_outdated.csv"
    _run_python_script(
        [
            NIX_OUTDATED,
            "--out",
            out_path_nix_outdated.as_posix(),
            TEST_NIX_RESULT,
        ]
    )
    assert out_path_nix_outdated.exists()


################################################################################


def test_whitelist():
    """Test applying whitelist to vulnerability csv file"""
    # Load test files
    whitelist_csv = MYDIR / "resources" / "whitelist.csv"
    assert whitelist_csv.exists()
    vulns_csv = MYDIR / "resources" / "vulns.csv"
    assert vulns_csv.exists()
    df_whitelist = load_whitelist(whitelist_csv)
    assert df_whitelist is not None
    df_vulns = df_from_csv_file(vulns_csv)
    assert df_vulns is not None
    print("df_vulns:")
    print(df_vulns.info())
    print(df_vulns)
    print("whitelist:")
    print(df_whitelist)
    # Copy df_vulns, including only the columns we want to include in the diff
    df_vuln_id_copy = df_vulns.copy()[["vuln_id", "package"]]
    print("df_vuln_id_copy:")
    print(df_vuln_id_copy)
    # Apply whitelist, this changes df_vuln_id_copy in-place
    # by adding columns "whitelist" and "whitelist_comment"
    df_apply_whitelist(df_whitelist, df_vuln_id_copy)
    print("df_vuln_id_copy after whitelist apply")
    print(df_vuln_id_copy.info())
    print(df_vuln_id_copy)
    # After applying whitelist, the resulting dataframe should match df_vulns
    df_diff = df_difference(df_vulns.astype(str), df_vuln_id_copy.astype(str))
    print("diff")
    print(df_diff)
    assert df_diff.empty, df_to_string(df_diff)


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
    # Re-order columns: last column ('_merge') becomes first
    cols = df.columns.tolist()
    cols = cols[-1:] + cols[:-1]
    df = df[cols]
    return df


################################################################################


if __name__ == "__main__":
    pytest.main([__file__])


################################################################################
