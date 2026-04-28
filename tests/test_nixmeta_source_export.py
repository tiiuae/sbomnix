#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-function-docstring

"""Tests for SBOM-level nixpkgs metadata source export."""

import uuid

import pandas as pd

from sbomnix.meta import NixpkgsMetaSource
from sbomnix.sbomdb import SbomDb


def _make_minimal_sbomdb():
    sbomdb = object.__new__(SbomDb)
    sbomdb.uid = "store_path"
    sbomdb.nix_path = "/nix/store/target"
    sbomdb.buildtime = False
    sbomdb.target_deriver = "/nix/store/target.drv"
    sbomdb.depth = None
    sbomdb.uuid = uuid.uuid4()
    sbomdb.sbom_type = "runtime_only"
    sbomdb.nixpkgs_meta_source = NixpkgsMetaSource(
        method="flakeref-target",
        path="/nix/store/source",
        rev="1234",
        flakeref=".#target",
        version="25.11",
        message="base nixpkgs source metadata",
    )
    sbomdb.df_sbomdb = pd.DataFrame(
        [
            {
                "store_path": "/nix/store/target.drv",
                "pname": "target",
                "name": "target",
                "version": "1.0",
                "outputs": ["/nix/store/target"],
                "out": "/nix/store/target",
                "purl": "",
                "cpe": "",
                "urls": "",
                "patches": "",
            }
        ]
    )
    return sbomdb


def test_cdx_document_records_nixpkgs_metadata_source(monkeypatch):
    sbomdb = _make_minimal_sbomdb()
    monkeypatch.setattr(SbomDb, "lookup_dependencies", lambda *_args, **_kwargs: None)

    cdx = sbomdb.to_cdx_data()

    properties = {prop["name"]: prop["value"] for prop in cdx["metadata"]["properties"]}
    assert properties["nixpkgs:metadata_source_method"] == "flakeref-target"
    assert properties["nixpkgs:path"] == "/nix/store/source"
    assert properties["nixpkgs:rev"] == "1234"
    assert properties["nixpkgs:flakeref"] == ".#target"
    assert properties["nixpkgs:version"] == "25.11"
    assert properties["nixpkgs:message"] == "base nixpkgs source metadata"


def test_spdx_document_records_nixpkgs_metadata_source(monkeypatch):
    sbomdb = _make_minimal_sbomdb()
    monkeypatch.setattr(SbomDb, "lookup_dependencies", lambda *_args, **_kwargs: None)

    spdx = sbomdb.to_spdx_data()

    assert "included dependencies: 'runtime_only'" in spdx["comment"]
    assert (
        "nixpkgs metadata source: metadata_source_method=flakeref-target"
        in spdx["comment"]
    )
    assert "path=/nix/store/source" in spdx["comment"]
    assert "rev=1234" in spdx["comment"]
    assert "message=base nixpkgs source metadata" in spdx["comment"]
    assert "warning=" not in spdx["comment"]
