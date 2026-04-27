#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the dependency comparison test harness."""

import pandas as pd

from tests.compare_deps import compare_dependencies


def test_compare_dependencies_filters_darwin_buildtime_source_paths():
    """Darwin nixgraph output may include graph-only source paths without derivers."""
    target_drv = "/nix/store/hash-hello-2.12.3.drv"
    dependency_drv = "/nix/store/hash-dependency.drv"
    graph_only_paths = [
        "/nix/store/hash-meson.build.in",
        "/nix/store/hash-Info.plist",
        "/nix/store/hash-meson.options",
        "/nix/store/hash-meson.build",
        "/nix/store/hash-lua-setup-hook",
        "/nix/store/hash-remove-references-to",
        "/nix/store/hash-Architectures.xcspec",
        "/nix/store/hash-ToolchainInfo.plist",
        "/nix/store/hash-ProductTypes.xcspec",
        "/nix/store/hash-PackageTypes.xcspec",
    ]

    df_sbom = pd.DataFrame(
        {
            "drv_path": [target_drv, dependency_drv],
            "output_path": ["/nix/store/hash-hello", "/nix/store/hash-dependency"],
            "ref": [target_drv, dependency_drv],
            "depends_on": [dependency_drv, ""],
        }
    )
    df_graph = pd.DataFrame(
        {
            "target_path": [target_drv] * (1 + len(graph_only_paths)),
            "src_path": [dependency_drv, *graph_only_paths],
        }
    )

    assert compare_dependencies(
        df_sbom,
        df_graph,
        sbom_type="runtime_and_buildtime",
        graph_type="buildtime",
    )
