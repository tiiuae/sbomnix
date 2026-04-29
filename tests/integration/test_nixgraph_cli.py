#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CLI integration tests for nixgraph and dependency comparisons."""

from textwrap import dedent

import pandas as pd
import pytest

from tests.testpaths import COMPARE_DEPS, NIXGRAPH, SBOMNIX
from tests.testutils import df_difference, df_to_string


def _write_nixgraph_test_flake(flake_dir):
    flake_dir.mkdir()
    (flake_dir / "flake.nix").write_text(
        dedent(
            """
            {
              outputs = { self }:
                let
                  mkPackage = system:
                    let
                      mkTestDerivation =
                        { name, pname, version, command }:
                        builtins.derivation {
                          inherit name pname system version;
                          builder = "/bin/sh";
                          args = [ "-c" command ];
                        };

                      first = mkTestDerivation {
                        name = "sbomnix-flake-first-1.0";
                        pname = "sbomnix-flake-first";
                        version = "1.0";
                        command = "echo first > $out";
                      };

                      second = mkTestDerivation {
                        name = "sbomnix-flake-second-1.0";
                        pname = "sbomnix-flake-second";
                        version = "1.0";
                        command = "echo ${first} > $out";
                      };
                    in
                    mkTestDerivation {
                      name = "sbomnix-flake-third-1.0";
                      pname = "sbomnix-flake-third";
                      version = "1.0";
                      command = "echo ${second} > $out";
                    };
                in
                {
                  packages.x86_64-linux.default = mkPackage "x86_64-linux";
                  packages.aarch64-linux.default = mkPackage "aarch64-linux";
                  packages.x86_64-darwin.default = mkPackage "x86_64-darwin";
                  packages.aarch64-darwin.default = mkPackage "aarch64-darwin";
                };
            }
            """
        ),
        encoding="utf-8",
    )
    return f"{flake_dir.as_posix()}#"


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


def test_nixgraph_csv_runtime_drv(_run_python_script, test_nix_drv, test_work_dir):
    """Test nixgraph runtime graph generation from a direct derivation path."""
    csv_out = test_work_dir / "graph_runtime_drv.csv"
    _run_python_script([NIXGRAPH, test_nix_drv, "--out", csv_out, "--depth", "3"])
    assert csv_out.exists()
    df_out = pd.read_csv(csv_out)
    assert not df_out.empty
    assert set(df_out["target_pname"]) >= {
        "sbomnix-test-third-1.0",
        "sbomnix-test-second-1.0",
    }


def test_nixgraph_csv_buildtime(_run_python_script, test_nix_drv, test_work_dir):
    """Test nixgraph with buildtime csv output generates valid csv."""
    csv_out = test_work_dir / "graph_buildtime.csv"
    _run_python_script([NIXGRAPH, test_nix_drv, "--out", csv_out, "--buildtime"])
    assert csv_out.exists()
    df_out = pd.read_csv(csv_out)
    assert not df_out.empty


def test_nixgraph_dot_includes_edges_labels_and_style(
    _run_python_script,
    test_nix_result,
    test_work_dir,
):
    """Test DOT output for graph shape, labels, pathnames, and colorized nodes."""
    dot_out = test_work_dir / "graph.dot"
    _run_python_script(
        [
            NIXGRAPH,
            test_nix_result,
            "--out",
            dot_out,
            "--depth=3",
            "--pathnames",
            "--colorize=.*second.*",
        ]
    )
    dot = dot_out.read_text(encoding="utf-8")
    assert "->" in dot
    assert "sbomnix-test-third-1.0" in dot
    assert "sbomnix-test-second-1.0" in dot
    assert "<BR/>" in dot
    assert 'fillcolor="#FFE6E6"' in dot


def test_nixgraph_depth_and_until_limit_traversal(
    _run_python_script,
    test_nix_result,
    test_work_dir,
):
    """Test traversal limiting with --depth and --until."""
    depth_one_csv = test_work_dir / "graph_depth_one.csv"
    _run_python_script(
        [
            NIXGRAPH,
            test_nix_result,
            "--out",
            depth_one_csv,
            "--depth=1",
        ]
    )
    df_depth_one = pd.read_csv(depth_one_csv)
    assert df_depth_one["graph_depth"].max() == 1

    until_dot = test_work_dir / "graph_until.dot"
    _run_python_script(
        [
            NIXGRAPH,
            test_nix_result,
            "--out",
            until_dot,
            "--depth=100",
            "--until=.*second.*",
        ]
    )
    dot = until_dot.read_text(encoding="utf-8")
    assert "sbomnix-test-second-1.0" in dot
    assert "sbomnix-test-first-1.0" not in dot


def test_nixgraph_csv_runtime_flakeref(_run_python_script, test_work_dir):
    """Test nixgraph runtime graph generation from a flakeref."""
    flakeref = _write_nixgraph_test_flake(test_work_dir / "runtime-flake")
    csv_out = test_work_dir / "graph_runtime_flake.csv"
    _run_python_script([NIXGRAPH, flakeref, "--out", csv_out, "--depth=3"])
    assert csv_out.exists()
    df_out = pd.read_csv(csv_out)
    assert set(df_out["target_pname"]) >= {
        "sbomnix-flake-third-1.0",
        "sbomnix-flake-second-1.0",
    }


def test_nixgraph_csv_buildtime_flakeref(_run_python_script, test_work_dir):
    """Test nixgraph buildtime graph generation from a flakeref."""
    flakeref = _write_nixgraph_test_flake(test_work_dir / "buildtime-flake")
    csv_out = test_work_dir / "graph_buildtime_flake.csv"
    _run_python_script(
        [NIXGRAPH, flakeref, "--out", csv_out, "--buildtime", "--depth=3"]
    )
    assert csv_out.exists()
    df_out = pd.read_csv(csv_out)
    assert set(df_out["target_pname"]) >= {
        "sbomnix-flake-third-1.0.drv",
        "sbomnix-flake-second-1.0.drv",
    }


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
def test_compare_deps_buildtime(_run_python_script, test_nix_drv, test_work_dir):
    """Compare nixgraph vs sbom buildtime dependencies."""
    graph_csv_out = test_work_dir / "graph.csv"
    _run_python_script(
        [
            NIXGRAPH,
            test_nix_drv,
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
            test_nix_drv,
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
