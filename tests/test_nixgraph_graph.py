#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for nixgraph parsing and traversal."""

from types import SimpleNamespace

import pandas as pd
import pytest

from nixgraph import graph as nixgraph_graph
from nixgraph.parsing import parse_nix_query_out
from nixgraph.render import NixDependencyGraph, NixGraphFilter
from sbomnix.closure import dependency_rows_to_dataframe
from sbomnix.runtime import RuntimeClosure


class CapturingLogger:
    def __init__(self):
        self.records = []

    def debug(self, msg, *args):
        self.records.append(("debug", msg, args))

    def info(self, msg, *args):
        self.records.append(("info", msg, args))

    def log(self, level, msg, *args):
        self.records.append(("log", level, msg, args))


def test_parse_nix_query_out_extracts_dependency_edges():
    """Parse nix-store graph output into structured dependency edges."""
    nix_query_out = "\n".join(
        [
            '"11111111111111111111111111111111-bash-5.1"'
            ' -> "22222222222222222222222222222222-hello-2.12.1"',
            "not a dependency line",
            '"33333333333333333333333333333333-glibc-2.39"'
            ' -> "11111111111111111111111111111111-bash-5.1"',
        ]
    )

    dependencies = parse_nix_query_out(nix_query_out, "/custom/store/")
    dependency_dicts = sorted(
        (dependency.to_dict() for dependency in dependencies),
        key=lambda entry: (entry["target_path"], entry["src_path"]),
    )

    assert dependency_dicts == [
        {
            "src_path": "/custom/store/33333333333333333333333333333333-glibc-2.39",
            "src_pname": "glibc-2.39",
            "target_path": "/custom/store/11111111111111111111111111111111-bash-5.1",
            "target_pname": "bash-5.1",
        },
        {
            "src_path": "/custom/store/11111111111111111111111111111111-bash-5.1",
            "src_pname": "bash-5.1",
            "target_path": "/custom/store/22222222222222222222222222222222-hello-2.12.1",
            "target_pname": "hello-2.12.1",
        },
    ]


def test_nixgraph_filter_get_query_str_joins_fields():
    """Render a stable pandas query string from the active filter fields."""
    nixfilter = NixGraphFilter(
        src_path="/nix/store/source",
        target_path="/nix/store/target",
    )

    assert (
        nixfilter.get_query_str()
        == "src_path == '/nix/store/source' and target_path == '/nix/store/target'"
    )


def test_dependency_graph_returns_dataframe_for_csv_output():
    """Return the traversed graph rows directly when CSV mode is requested."""
    df_dependencies = pd.DataFrame.from_records(
        [
            {
                "src_path": "/nix/store/bash",
                "src_pname": "bash",
                "target_path": "/nix/store/hello",
                "target_pname": "hello",
            },
            {
                "src_path": "/nix/store/glibc",
                "src_pname": "glibc",
                "target_path": "/nix/store/bash",
                "target_pname": "bash",
            },
        ]
    )
    args = SimpleNamespace(
        out="graph.csv",
        depth=3,
        inverse=None,
        until=None,
        colorize=None,
        pathnames=False,
        return_df=True,
    )

    df_out = NixDependencyGraph(df_dependencies).draw("/nix/store/hello", args)
    df_out = df_out.sort_values(["graph_depth", "src_path"]).reset_index(drop=True)

    assert list(df_out["graph_depth"]) == [1, 2]
    assert list(df_out["target_path"]) == ["/nix/store/hello", "/nix/store/bash"]
    assert list(df_out["src_path"]) == ["/nix/store/bash", "/nix/store/glibc"]


def test_nix_dependencies_logs_dependency_loading_at_info(monkeypatch):
    logger = CapturingLogger()
    monkeypatch.setattr(nixgraph_graph, "LOG", logger)
    monkeypatch.setattr(
        nixgraph_graph,
        "load_runtime_closure",
        lambda *_args, **_kwargs: RuntimeClosure(
            df_deps=dependency_rows_to_dataframe([]),
            output_paths_by_drv={},
        ),
    )

    nixgraph_graph.NixDependencies("/nix/store/target")

    assert (
        "info",
        "Loading %s dependencies referenced by '%s'",
        ("runtime", "/nix/store/target"),
    ) in logger.records


def test_nix_dependencies_buildtime_uses_derivation_json(monkeypatch):
    drv_infos = {
        "/nix/store/11111111111111111111111111111111-target.drv": {
            "inputDrvs": {
                "/nix/store/22222222222222222222222222222222-dep.drv": ["out"],
            }
        }
    }
    monkeypatch.setattr(
        nixgraph_graph,
        "load_recursive",
        lambda path: ({path: object()}, drv_infos),
    )
    monkeypatch.setattr(
        nixgraph_graph,
        "buildtime_query_output",
        lambda *_args, **_kwargs: pytest.fail("legacy buildtime query called"),
        raising=False,
    )

    deps = nixgraph_graph.NixDependencies(
        "/nix/store/target.drv",
        buildtime=True,
        drv_path="/nix/store/11111111111111111111111111111111-target.drv",
    )

    assert deps.start_path == "/nix/store/11111111111111111111111111111111-target.drv"
    assert deps.to_dataframe().to_dict("records") == [
        {
            "src_path": "/nix/store/22222222222222222222222222222222-dep.drv",
            "src_pname": "dep.drv",
            "target_path": "/nix/store/11111111111111111111111111111111-target.drv",
            "target_pname": "target.drv",
        }
    ]


def test_nix_dependencies_runtime_uses_resolved_output_path(monkeypatch):
    calls = []
    monkeypatch.setattr(
        nixgraph_graph,
        "find_deriver_path",
        lambda *_args, **_kwargs: calls.append("find_deriver_path"),
    )
    monkeypatch.setattr(
        nixgraph_graph,
        "find_output_path",
        lambda *_args, **_kwargs: calls.append("find_output_path"),
        raising=False,
    )
    monkeypatch.setattr(
        nixgraph_graph,
        "runtime_query_output",
        lambda *_args, **_kwargs: calls.append("runtime_query_output"),
        raising=False,
    )
    monkeypatch.setattr(
        nixgraph_graph,
        "load_runtime_closure",
        lambda *_args, **_kwargs: RuntimeClosure(
            df_deps=dependency_rows_to_dataframe(
                [
                    {
                        "src_path": "/nix/store/dep",
                        "src_pname": "dep",
                        "target_path": "/nix/store/target",
                        "target_pname": "target",
                    }
                ]
            ),
            output_paths_by_drv={},
        ),
    )

    deps = nixgraph_graph.NixDependencies(
        "/nix/store/target",
        drv_path="/nix/store/target.drv",
        resolve_output=False,
    )

    assert deps.start_path == "/nix/store/target"
    assert calls == []
    assert deps.to_dataframe().to_dict("records") == [
        {
            "src_path": "/nix/store/dep",
            "src_pname": "dep",
            "target_path": "/nix/store/target",
            "target_pname": "target",
        }
    ]
