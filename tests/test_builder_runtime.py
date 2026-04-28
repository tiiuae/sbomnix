#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for SBOM builder runtime closure selection."""

import pandas as pd
import pytest

from sbomnix import builder as sbomnix_builder
from sbomnix.builder import SbomBuilder
from sbomnix.closure import dependency_rows_to_dataframe
from sbomnix.runtime import RuntimeClosure

TARGET_PATH = "/nix/store/11111111111111111111111111111111-target-1.0"
TARGET_DERIVER = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-target-1.0.drv"
GRAPH_ONLY_PATH = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source"


def _builder_double():
    builder = object.__new__(SbomBuilder)
    builder.nix_path = TARGET_PATH
    builder.buildtime = False
    builder.target_deriver = TARGET_DERIVER
    builder.include_cpe = False
    builder.depth = None
    builder.df_deps = None
    builder._runtime_output_paths_by_drv = None
    return builder


def _runtime_closure(output_paths_by_drv, rows=None):
    return RuntimeClosure(
        df_deps=dependency_rows_to_dataframe([] if rows is None else rows),
        output_paths_by_drv=output_paths_by_drv,
    )


def test_runtime_path_info_dependencies_accepts_existing_derivers(monkeypatch):
    closure = _runtime_closure({TARGET_DERIVER: {TARGET_PATH}})
    monkeypatch.setattr(
        sbomnix_builder,
        "load_runtime_closure",
        lambda _path: closure,
    )
    monkeypatch.setattr(
        sbomnix_builder,
        "is_loadable_deriver_path",
        lambda path: path == TARGET_DERIVER,
    )

    builder = _builder_double()

    assert builder._init_runtime_path_info_dependencies(TARGET_PATH) is True
    assert builder._runtime_output_paths_by_drv == {TARGET_DERIVER: {TARGET_PATH}}
    assert builder.df_deps.equals(closure.df_deps)


def test_runtime_components_fall_back_when_derivation_loading_fails(monkeypatch):
    fallback_rows = [
        {
            "src_path": GRAPH_ONLY_PATH,
            "src_pname": "source",
            "target_path": TARGET_PATH,
            "target_pname": "target-1.0",
        }
    ]
    fallback_deps = dependency_rows_to_dataframe(fallback_rows)
    calls = {}

    def fail_runtime_components(*_args, **_kwargs):
        raise ValueError("broken derivation metadata")

    def fake_init_nix_store_dependencies(builder, nix_path):
        calls["nix_path"] = nix_path
        builder.df_deps = fallback_deps

    def fake_load_fallback_store_dataframe(_builder, paths):
        calls["fallback_paths"] = paths
        return pd.DataFrame.from_records(
            [
                {
                    "store_path": TARGET_DERIVER,
                    "outputs": [TARGET_PATH],
                }
            ]
        )

    monkeypatch.setattr(
        sbomnix_builder,
        "runtime_derivations_to_dataframe",
        fail_runtime_components,
    )
    monkeypatch.setattr(
        SbomBuilder,
        "_init_nix_store_dependencies",
        fake_init_nix_store_dependencies,
    )
    monkeypatch.setattr(
        SbomBuilder,
        "_load_fallback_store_dataframe",
        fake_load_fallback_store_dataframe,
    )

    builder = _builder_double()
    builder._runtime_output_paths_by_drv = {TARGET_DERIVER: {TARGET_PATH}}

    df_components = builder._init_runtime_components({TARGET_PATH})

    assert calls == {
        "nix_path": TARGET_PATH,
        "fallback_paths": {GRAPH_ONLY_PATH, TARGET_PATH},
    }
    assert builder._runtime_output_paths_by_drv is None
    assert builder.df_deps.equals(fallback_deps)
    assert df_components.to_dict("records") == [
        {
            "store_path": TARGET_DERIVER,
            "outputs": [TARGET_PATH],
        }
    ]


@pytest.mark.parametrize(
    "deriver",
    [
        "unknown-deriver",
        "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-target-1.0",
        "/nix/store/cccccccccccccccccccccccccccccccc-missing-1.0.drv",
    ],
)
def test_runtime_path_info_dependencies_uses_output_queries_for_unloadable_derivers(
    monkeypatch,
    deriver,
):
    closure = _runtime_closure({deriver: {TARGET_PATH}})
    monkeypatch.setattr(
        sbomnix_builder,
        "load_runtime_closure",
        lambda _path: closure,
    )
    monkeypatch.setattr(
        sbomnix_builder,
        "is_loadable_deriver_path",
        lambda _path: False,
    )

    builder = _builder_double()

    assert builder._init_runtime_path_info_dependencies(TARGET_PATH) is True
    assert builder._runtime_output_paths_by_drv == {TARGET_PATH: {TARGET_PATH}}
    assert builder.df_deps.equals(closure.df_deps)


def test_runtime_path_info_dependencies_accepts_graph_only_references(monkeypatch):
    rows = [
        {
            "src_path": GRAPH_ONLY_PATH,
            "src_pname": "source",
            "target_path": TARGET_PATH,
            "target_pname": "target-1.0",
        }
    ]
    closure = _runtime_closure({TARGET_DERIVER: {TARGET_PATH}}, rows=rows)
    monkeypatch.setattr(
        sbomnix_builder,
        "load_runtime_closure",
        lambda _path: closure,
    )
    monkeypatch.setattr(
        sbomnix_builder,
        "is_loadable_deriver_path",
        lambda path: path == TARGET_DERIVER,
    )

    builder = _builder_double()

    assert builder._init_runtime_path_info_dependencies(TARGET_PATH) is True
    assert builder._runtime_output_paths_by_drv == {TARGET_DERIVER: {TARGET_PATH}}
    assert builder.df_deps.equals(closure.df_deps)
