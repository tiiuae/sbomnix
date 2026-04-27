#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for nixgraph parsing and traversal."""

from types import SimpleNamespace

import pandas as pd

from nixgraph.parsing import parse_nix_query_out
from nixgraph.render import NixDependencyGraph, NixGraphFilter


def test_parse_nix_query_out_extracts_dependency_edges():
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
    nixfilter = NixGraphFilter(
        src_path="/nix/store/source",
        target_path="/nix/store/target",
    )

    assert (
        nixfilter.get_query_str()
        == "src_path == '/nix/store/source' and target_path == '/nix/store/target'"
    )


def test_dependency_graph_returns_dataframe_for_csv_output():
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
