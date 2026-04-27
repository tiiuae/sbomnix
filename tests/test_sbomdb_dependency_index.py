#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for indexed SBOM dependency lookups."""

import pandas as pd

from sbomnix.dependency_index import build_dependency_index


def test_build_dependency_index_combines_runtime_and_buildtime_edges():
    """Index both output-path and derivation-path dependencies for one component."""
    df_sbomdb = pd.DataFrame(
        [
            {
                "store_path": "/nix/store/target.drv",
                "purl": "pkg:nix/target@1.0",
                "outputs": ["/nix/store/target-out"],
            },
            {
                "store_path": "/nix/store/runtime-dep.drv",
                "purl": "pkg:nix/runtime-dep@1.0",
                "outputs": ["/nix/store/runtime-dep-out"],
            },
            {
                "store_path": "/nix/store/build-dep.drv",
                "purl": "pkg:nix/build-dep@1.0",
                "outputs": ["/nix/store/build-dep-out"],
            },
        ]
    )
    df_outputs = df_sbomdb.explode("outputs")
    df_deps = pd.DataFrame(
        [
            {
                "src_path": "/nix/store/runtime-dep-out",
                "target_path": "/nix/store/target-out",
            },
            {
                "src_path": "/nix/store/build-dep.drv",
                "target_path": "/nix/store/target.drv",
            },
        ]
    )

    index = build_dependency_index(df_deps, df_sbomdb, df_outputs, uid="store_path")
    target_drv = next(df_sbomdb.itertuples())

    assert index.lookup(target_drv) == [
        "/nix/store/build-dep.drv",
        "/nix/store/runtime-dep.drv",
    ]
    assert index.lookup(target_drv, uid="purl") == [
        "pkg:nix/build-dep@1.0",
        "pkg:nix/runtime-dep@1.0",
    ]


def test_build_dependency_index_returns_none_without_dependencies():
    """Return no lookup entries when the component has no indexed dependencies."""
    df_sbomdb = pd.DataFrame(
        [
            {
                "store_path": "/nix/store/target.drv",
                "purl": "pkg:nix/target@1.0",
                "outputs": ["/nix/store/target-out"],
            }
        ]
    )
    index = build_dependency_index(
        pd.DataFrame(),
        df_sbomdb,
        df_sbomdb.explode("outputs"),
        uid="store_path",
    )

    assert index.lookup(next(df_sbomdb.itertuples())) is None
