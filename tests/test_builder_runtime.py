#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for SBOM builder runtime closure selection."""

import pandas as pd
import pytest

from common import columns as cols
from common.errors import MissingNixDerivationMetadataError, SbomnixError
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
    builder.target_component_ref = None
    builder.include_cpe = False
    builder.depth = None
    builder.df_deps = None
    builder._runtime_output_paths_by_load_path = None
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

    loaded = builder._load_runtime_path_info_closure(TARGET_PATH)
    builder._init_dependencies(loaded)

    assert loaded.runtime_output_paths_by_load_path == {TARGET_DERIVER: {TARGET_PATH}}
    assert builder._runtime_output_paths_by_load_path == {TARGET_DERIVER: {TARGET_PATH}}
    assert builder.df_deps.equals(closure.df_deps)


def test_runtime_components_propagate_derivation_loading_failures(monkeypatch):
    def fail_runtime_components(*_args, **_kwargs):
        raise ValueError("broken derivation metadata")

    monkeypatch.setattr(
        sbomnix_builder,
        "runtime_derivations_to_dataframe",
        fail_runtime_components,
    )

    builder = _builder_double()
    builder._runtime_output_paths_by_load_path = {TARGET_DERIVER: {TARGET_PATH}}

    with pytest.raises(ValueError, match="broken derivation metadata"):
        builder._init_runtime_components({TARGET_PATH})

    assert builder._runtime_output_paths_by_load_path == {TARGET_DERIVER: {TARGET_PATH}}


def test_runtime_components_reject_missing_derivation_metadata(monkeypatch):
    monkeypatch.setattr(
        sbomnix_builder,
        "runtime_derivations_to_dataframe",
        lambda *_args, **_kwargs: pd.DataFrame(),
    )

    builder = _builder_double()
    builder._runtime_output_paths_by_load_path = {TARGET_PATH: {TARGET_PATH}}

    with pytest.raises(MissingNixDerivationMetadataError, match=TARGET_PATH):
        builder._init_runtime_components({TARGET_PATH})


def test_runtime_deriver_lookup_preserves_typed_errors(monkeypatch):
    def fail_find_deriver(_path):
        raise SbomnixError("schema drift")

    monkeypatch.setattr(sbomnix_builder, "find_deriver", fail_find_deriver)

    builder = _builder_double()

    with pytest.raises(SbomnixError, match="schema drift"):
        builder._resolve_target_deriver(TARGET_PATH)


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

    loaded = builder._load_runtime_path_info_closure(TARGET_PATH)
    builder._init_dependencies(loaded)

    assert loaded.runtime_output_paths_by_load_path == {TARGET_PATH: {TARGET_PATH}}
    assert builder._runtime_output_paths_by_load_path == {TARGET_PATH: {TARGET_PATH}}
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

    loaded = builder._load_runtime_path_info_closure(TARGET_PATH)
    builder._init_dependencies(loaded)

    assert loaded.runtime_output_paths_by_load_path == {TARGET_DERIVER: {TARGET_PATH}}
    assert builder._runtime_output_paths_by_load_path == {TARGET_DERIVER: {TARGET_PATH}}
    assert builder.df_deps.equals(closure.df_deps)


def test_runtime_path_info_dependencies_supports_targets_without_derivers(
    monkeypatch,
):
    closure = _runtime_closure({})
    monkeypatch.setattr(
        sbomnix_builder,
        "load_runtime_closure",
        lambda _path: closure,
    )

    builder = _builder_double()
    builder.target_deriver = None

    loaded = builder._load_runtime_path_info_closure(TARGET_PATH)
    builder._init_dependencies(loaded)

    assert loaded.runtime_output_paths_by_load_path == {TARGET_PATH: {TARGET_PATH}}
    assert builder._runtime_output_paths_by_load_path == {TARGET_PATH: {TARGET_PATH}}


def test_target_component_ref_uses_runtime_output_when_deriver_is_unavailable():
    builder = _builder_double()
    builder.target_deriver = None
    builder.df_sbomdb = pd.DataFrame(
        [
            {
                cols.STORE_PATH: "/nix/store/runtime-load-path",
                cols.OUTPUTS: [TARGET_PATH],
            }
        ]
    )

    assert builder._resolve_target_component_ref() == "/nix/store/runtime-load-path"


def test_target_component_ref_skips_missing_outputs_when_deriver_is_unavailable():
    builder = _builder_double()
    builder.target_deriver = None
    builder.df_sbomdb = pd.DataFrame(
        [
            {
                cols.STORE_PATH: "/nix/store/no-outputs",
                cols.OUTPUTS: float("nan"),
            },
            {
                cols.STORE_PATH: "/nix/store/runtime-load-path",
                cols.OUTPUTS: [TARGET_PATH],
            },
        ]
    )

    assert builder._resolve_target_component_ref() == "/nix/store/runtime-load-path"


def test_target_component_ref_handles_non_identifier_output_column(monkeypatch):
    monkeypatch.setattr(cols, "OUTPUTS", "store-outputs")
    builder = _builder_double()
    builder.target_deriver = None
    builder.df_sbomdb = pd.DataFrame(
        [
            {
                cols.STORE_PATH: "/nix/store/runtime-load-path",
                cols.OUTPUTS: [TARGET_PATH],
            }
        ]
    )

    assert builder._resolve_target_component_ref() == "/nix/store/runtime-load-path"


def test_target_component_ref_rejects_missing_runtime_target_metadata():
    builder = _builder_double()
    builder.target_deriver = None
    builder.df_sbomdb = pd.DataFrame(
        [
            {
                cols.STORE_PATH: "/nix/store/runtime-load-path",
                cols.OUTPUTS: ["/nix/store/other-output"],
            }
        ]
    )

    with pytest.raises(MissingNixDerivationMetadataError, match=TARGET_PATH):
        builder._resolve_target_component_ref()
