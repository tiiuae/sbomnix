#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for SBOM builder metadata joins."""

import pandas as pd

from common import columns as cols
from common.log import LOG, LOG_VERBOSE
from sbomnix import builder as sbomnix_builder
from sbomnix.builder import SbomBuilder
from sbomnix.meta_source import NixpkgsMetaSource


def _builder_double():
    builder = object.__new__(SbomBuilder)
    builder.nix_path = "/nix/store/target"
    builder.buildtime = False
    builder.target_deriver = None
    builder.flakeref = ".#target"
    builder.original_ref = ".#target"
    builder.impure = False
    builder.meta = None
    builder.nixpkgs_meta_source = NixpkgsMetaSource(method="disabled")
    return builder


def test_join_meta_leaves_precise_needed_rows_blank(monkeypatch):
    fake_df_meta = pd.DataFrame(
        [
            {
                cols.NAME: "hello-1.0",
                "pname": "hello",
                cols.VERSION: "1.0",
                "meta_ambiguous": "False",
                "meta_precise_needed": "False",
                "meta_description": "hello package",
                "meta_homepage": "https://example.invalid/hello",
                "meta_debug_private": "do-not-export",
            },
            {
                cols.NAME: "cornelis-0.2.0.1",
                "pname": "cornelis",
                cols.VERSION: "0.2.0.1",
                "meta_ambiguous": "True",
                "meta_precise_needed": "True",
                "meta_description": "top-level cornelis",
                "meta_debug_private": "do-not-export",
            },
        ]
    )

    class FakeMeta:
        def get_nixpkgs_meta_with_source(self, **_kwargs):
            return fake_df_meta, NixpkgsMetaSource(method="flake-meta")

    monkeypatch.setattr(sbomnix_builder, "Meta", FakeMeta)

    builder = _builder_double()
    builder.df_sbomdb = pd.DataFrame(
        [
            {cols.STORE_PATH: "/nix/store/hello-1.0.drv", cols.NAME: "hello-1.0"},
            {
                cols.STORE_PATH: "/nix/store/cornelis-top.drv",
                cols.NAME: "cornelis-0.2.0.1",
            },
            {
                cols.STORE_PATH: "/nix/store/cornelis-hs.drv",
                cols.NAME: "cornelis-0.2.0.1",
            },
        ]
    )

    builder._join_meta()

    by_store = {
        row[cols.STORE_PATH]: row.get("meta_description", "")
        for row in builder.df_sbomdb.to_dict("records")
    }
    assert by_store["/nix/store/hello-1.0.drv"] == "hello package"
    assert by_store["/nix/store/cornelis-top.drv"] != "top-level cornelis"
    assert by_store["/nix/store/cornelis-hs.drv"] != "top-level cornelis"
    assert pd.isna(by_store["/nix/store/cornelis-top.drv"])
    assert pd.isna(by_store["/nix/store/cornelis-hs.drv"])
    assert builder.df_sbomdb.loc[0, "meta_homepage"] == "https://example.invalid/hello"
    assert "meta_ambiguous" not in builder.df_sbomdb.columns
    assert "meta_precise_needed" not in builder.df_sbomdb.columns
    assert "meta_debug_private" not in builder.df_sbomdb.columns


def test_join_meta_logs_ambiguous_names_at_verbose(monkeypatch, caplog):
    fake_df_meta = pd.DataFrame(
        [
            {
                cols.NAME: "cornelis-0.2.0.1",
                "pname": "cornelis",
                cols.VERSION: "0.2.0.1",
                "meta_ambiguous": "True",
                "meta_precise_needed": "True",
            },
        ]
    )

    class FakeMeta:
        def get_nixpkgs_meta_with_source(self, **_kwargs):
            return fake_df_meta, NixpkgsMetaSource(method="flake-meta")

    monkeypatch.setattr(sbomnix_builder, "Meta", FakeMeta)

    builder = _builder_double()
    builder.df_sbomdb = pd.DataFrame(
        [
            {
                cols.STORE_PATH: "/nix/store/cornelis-top.drv",
                cols.NAME: "cornelis-0.2.0.1",
            },
        ]
    )

    with caplog.at_level(LOG_VERBOSE, logger=LOG.name):
        builder._join_meta()

    records = [
        record
        for record in caplog.records
        if "Leaving nixpkgs metadata blank for" in record.getMessage()
    ]
    assert len(records) == 1
    assert records[0].levelno == LOG_VERBOSE
    assert records[0].levelname == "VERBOSE"
    assert records[0].getMessage() == (
        "Leaving nixpkgs metadata blank for 1 ambiguous package name(s)"
    )
