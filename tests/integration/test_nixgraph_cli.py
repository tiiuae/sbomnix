#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CLI integration tests for nixgraph and dependency comparisons."""

import pandas as pd
import pytest

from tests.testpaths import COMPARE_DEPS, NIXGRAPH, SBOMNIX
from tests.testutils import df_difference, df_to_string


def test_nixgraph_help(_run_python_script):
    """Test nixgraph command line argument: '-h'."""
    _run_python_script([NIXGRAPH, "-h"])


def test_nixgraph_png(_run_python_script, test_nix_result, test_work_dir):
    """Test nixgraph with png output generates valid png image."""
    png_out = test_work_dir / "graph.png"
    _run_python_script([NIXGRAPH, test_nix_result, "--out", png_out, "--depth", "3"])
    assert png_out.exists()


def test_nixgraph_csv(_run_python_script, test_nix_result, test_work_dir):
    """Test nixgraph with csv output generates valid csv."""
    csv_out = test_work_dir / "graph.csv"
    _run_python_script([NIXGRAPH, test_nix_result, "--out", csv_out, "--depth", "3"])
    assert csv_out.exists()
    df_out = pd.read_csv(csv_out)
    assert not df_out.empty


def test_nixgraph_csv_buildtime(_run_python_script, test_nix_result, test_work_dir):
    """Test nixgraph with buildtime csv output generates valid csv."""
    csv_out = test_work_dir / "graph_buildtime.csv"
    _run_python_script([NIXGRAPH, test_nix_result, "--out", csv_out, "--buildtime"])
    assert csv_out.exists()
    df_out = pd.read_csv(csv_out)
    assert not df_out.empty


def test_nixgraph_csv_graph_inverse(_run_python_script, test_nix_result, test_work_dir):
    """Test nixgraph with '--inverse' argument."""
    csv_out = test_work_dir / "graph.csv"
    _run_python_script(
        [
            NIXGRAPH,
            test_nix_result,
            "--out",
            csv_out,
            "--depth=100",
        ]
    )
    assert csv_out.exists()
    df_out = pd.read_csv(csv_out)
    assert not df_out.empty

    csv_out_inv = test_work_dir / "graph_inverse.csv"
    _run_python_script(
        [
            NIXGRAPH,
            test_nix_result,
            "--out",
            csv_out_inv,
            "--depth=100",
            "--inverse=.*",
        ]
    )
    assert csv_out_inv.exists()
    df_out_inv = pd.read_csv(csv_out_inv)
    assert not df_out_inv.empty

    df_out = df_out.drop("graph_depth", axis=1).sort_values(by=["src_path"])
    df_out_inv = df_out_inv.drop("graph_depth", axis=1).sort_values(by=["src_path"])
    df_diff = df_difference(df_out, df_out_inv)
    assert df_diff.empty, df_to_string(df_diff)


def test_compare_deps_runtime(_run_python_script, test_nix_result, test_work_dir):
    """Compare nixgraph vs sbom runtime dependencies."""
    graph_csv_out = test_work_dir / "graph.csv"
    _run_python_script(
        [
            NIXGRAPH,
            test_nix_result,
            "--out",
            graph_csv_out,
            "--depth=100",
        ]
    )
    assert graph_csv_out.exists()

    out_path_cdx = test_work_dir / "sbom_cdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_result,
            "--cdx",
            out_path_cdx.as_posix(),
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


@pytest.mark.slow
@pytest.mark.skip_in_ci
def test_compare_deps_buildtime(_run_python_script, test_nix_result, test_work_dir):
    """Compare nixgraph vs sbom buildtime dependencies."""
    graph_csv_out = test_work_dir / "graph.csv"
    _run_python_script(
        [
            NIXGRAPH,
            test_nix_result,
            "--out",
            graph_csv_out,
            "--depth=100",
            "--buildtime",
        ]
    )
    assert graph_csv_out.exists()

    out_path_cdx = test_work_dir / "sbom_cdx_test.json"
    _run_python_script(
        [
            SBOMNIX,
            test_nix_result,
            "--cdx",
            out_path_cdx.as_posix(),
            "--buildtime",
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
