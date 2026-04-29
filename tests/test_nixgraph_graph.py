#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for nixgraph loading and traversal."""

from types import SimpleNamespace

import pandas as pd

from nixgraph import graph as nixgraph_graph
from nixgraph import render as nixgraph_render
from nixgraph.render import NixDependencyGraph
from sbomnix.closure import dependency_rows_to_dataframe
from sbomnix.runtime import RuntimeClosure


class CapturingLogger:
    def __init__(self):
        self.records = []

    def debug(self, msg, *args):
        self.records.append(("debug", msg, args))

    def info(self, msg, *args):
        self.records.append(("info", msg, args))

    def warning(self, msg, *args):
        self.records.append(("warning", msg, args))

    def log(self, level, msg, *args):
        self.records.append(("log", level, msg, args))


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


def test_dependency_graph_inverse_returns_dataframe_for_csv_output():
    """Return inverse traversal rows through the shared dependency walker."""
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
        inverse="glibc",
        until=None,
        colorize=None,
        pathnames=False,
        return_df=True,
    )

    df_out = NixDependencyGraph(df_dependencies).draw("/nix/store/hello", args)
    df_out = df_out.sort_values(["graph_depth", "target_path"]).reset_index(drop=True)

    assert list(df_out["graph_depth"]) == [1, 2]
    assert list(df_out["target_path"]) == ["/nix/store/bash", "/nix/store/hello"]
    assert list(df_out["src_path"]) == ["/nix/store/glibc", "/nix/store/bash"]


def test_dependency_graph_writes_raw_dot_without_graphviz_render(tmp_path):
    class FakeDigraph:
        def __init__(self):
            self.saved = []
            self.rendered = []

        def save(self, filename):
            self.saved.append(filename)

        def render(self, **kwargs):
            self.rendered.append(kwargs)

    fake = FakeDigraph()
    graph = NixDependencyGraph(pd.DataFrame())
    graph.digraph = fake

    dot_path = tmp_path / "graph.dot"
    graph._render(dot_path.as_posix())

    assert fake.saved == [dot_path.as_posix()]
    assert fake.rendered == []


def test_dependency_graph_deduplicates_rendered_nodes():
    node_calls = []

    class FakeDigraph:
        def node(self, *args, **kwargs):
            node_calls.append((args, kwargs))

    graph = NixDependencyGraph(pd.DataFrame())
    graph.digraph = FakeDigraph()
    graph.nodes_drawn = set()

    graph._add_node("/nix/store/bash", "bash")
    graph._add_node("/nix/store/bash", "bash")

    assert len(node_calls) == 1


def test_dependency_graph_warns_before_large_graphviz_render(monkeypatch):
    logger = CapturingLogger()
    monkeypatch.setattr(nixgraph_render, "LOG", logger)
    monkeypatch.setattr(nixgraph_render, "GRAPHVIZ_RENDER_WARN_EDGES", 1)
    monkeypatch.setattr(NixDependencyGraph, "_render", lambda self, filename: None)
    df_dependencies = pd.DataFrame.from_records(
        [
            {
                "src_path": "/nix/store/bash",
                "src_pname": "bash",
                "target_path": "/nix/store/hello",
                "target_pname": "hello",
            },
        ]
    )
    args = SimpleNamespace(
        out="graph.png",
        depth=1,
        inverse=None,
        until=None,
        colorize=None,
        pathnames=False,
    )

    NixDependencyGraph(df_dependencies).draw("/nix/store/hello", args)

    assert (
        "warning",
        "Rendering %s dependency edges with Graphviz may be slow; "
        "use --out graph.csv or --out graph.dot for faster output.",
        (1,),
    ) in logger.records


def test_load_dependencies_logs_dependency_loading_at_info(monkeypatch):
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

    nixgraph_graph.load_dependencies("/nix/store/target")

    assert (
        "info",
        "Loading %s dependencies referenced by '%s'",
        ("runtime", "/nix/store/target"),
    ) in logger.records


def test_load_dependencies_buildtime_uses_derivation_json(monkeypatch):
    drv_infos = {
        "/nix/store/11111111111111111111111111111111-target.drv": {
            "inputs": {
                "drvs": {
                    "/nix/store/22222222222222222222222222222222-dep.drv": ["out"],
                },
                "srcs": [
                    "/nix/store/33333333333333333333333333333333-source",
                ],
            }
        }
    }
    monkeypatch.setattr(
        nixgraph_graph,
        "require_deriver",
        lambda path: path,
    )
    monkeypatch.setattr(
        nixgraph_graph,
        "load_recursive",
        lambda path: ({path: object()}, drv_infos),
    )

    deps = nixgraph_graph.load_dependencies(
        "/nix/store/target.drv",
        buildtime=True,
    )

    assert deps.start_path == "/nix/store/target.drv"
    assert deps.df.to_dict("records") == [
        {
            "src_path": "/nix/store/22222222222222222222222222222222-dep.drv",
            "src_pname": "dep.drv",
            "target_path": "/nix/store/11111111111111111111111111111111-target.drv",
            "target_pname": "target.drv",
        },
        {
            "src_path": "/nix/store/33333333333333333333333333333333-source",
            "src_pname": "source",
            "target_path": "/nix/store/11111111111111111111111111111111-target.drv",
            "target_pname": "target.drv",
        },
    ]


def test_load_dependencies_runtime_uses_resolved_output_path(monkeypatch):
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

    deps = nixgraph_graph.load_dependencies("/nix/store/target")

    assert deps.start_path == "/nix/store/target"
    assert deps.df.to_dict("records") == [
        {
            "src_path": "/nix/store/dep",
            "src_pname": "dep",
            "target_path": "/nix/store/target",
            "target_pname": "target",
        }
    ]


def test_nixgraph_no_longer_exposes_removed_graph_helpers():
    assert not hasattr(nixgraph_graph, "NixDependencies")
    assert not hasattr(nixgraph_graph, "parse_nix_query_out")
    assert not hasattr(nixgraph_graph, "runtime_query_output")
    assert not hasattr(nixgraph_graph, "buildtime_query_output")
    assert not hasattr(nixgraph_graph, "find_output_path")
