#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for SBOM dependency closure helpers."""

import pandas as pd

from sbomnix.closure import dependencies_to_depth, dependency_paths


def _dependency_df():
    return pd.DataFrame.from_records(
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
            {
                "src_path": "/nix/store/zlib",
                "src_pname": "zlib",
                "target_path": "/nix/store/glibc",
                "target_pname": "glibc",
            },
        ]
    )


def test_dependencies_to_depth_returns_reachable_dependency_rows():
    df_depth = dependencies_to_depth(_dependency_df(), "/nix/store/hello", depth=2)

    assert df_depth.to_dict("records") == [
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


def test_dependencies_to_depth_returns_empty_dataframe_for_missing_start():
    df_depth = dependencies_to_depth(_dependency_df(), "/nix/store/missing", depth=2)

    assert df_depth.empty
    assert list(df_depth.columns) == [
        "src_path",
        "src_pname",
        "target_path",
        "target_pname",
    ]


def test_dependencies_to_depth_deduplicates_shared_diamond_edges():
    df_deps = pd.DataFrame.from_records(
        [
            {
                "src_path": "/nix/store/left",
                "src_pname": "left",
                "target_path": "/nix/store/root",
                "target_pname": "root",
            },
            {
                "src_path": "/nix/store/right",
                "src_pname": "right",
                "target_path": "/nix/store/root",
                "target_pname": "root",
            },
            {
                "src_path": "/nix/store/shared",
                "src_pname": "shared",
                "target_path": "/nix/store/left",
                "target_pname": "left",
            },
            {
                "src_path": "/nix/store/shared",
                "src_pname": "shared",
                "target_path": "/nix/store/right",
                "target_pname": "right",
            },
            {
                "src_path": "/nix/store/leaf",
                "src_pname": "leaf",
                "target_path": "/nix/store/shared",
                "target_pname": "shared",
            },
        ]
    )

    df_depth = dependencies_to_depth(df_deps, "/nix/store/root", depth=3)

    assert df_depth.to_dict("records") == [
        {
            "src_path": "/nix/store/left",
            "src_pname": "left",
            "target_path": "/nix/store/root",
            "target_pname": "root",
        },
        {
            "src_path": "/nix/store/shared",
            "src_pname": "shared",
            "target_path": "/nix/store/left",
            "target_pname": "left",
        },
        {
            "src_path": "/nix/store/leaf",
            "src_pname": "leaf",
            "target_path": "/nix/store/shared",
            "target_pname": "shared",
        },
        {
            "src_path": "/nix/store/right",
            "src_pname": "right",
            "target_path": "/nix/store/root",
            "target_pname": "root",
        },
        {
            "src_path": "/nix/store/shared",
            "src_pname": "shared",
            "target_path": "/nix/store/right",
            "target_pname": "right",
        },
    ]


def test_dependency_paths_returns_all_source_and_target_paths():
    assert dependency_paths(_dependency_df()) == {
        "/nix/store/bash",
        "/nix/store/glibc",
        "/nix/store/hello",
        "/nix/store/zlib",
    }
