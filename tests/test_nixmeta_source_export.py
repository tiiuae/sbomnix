#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for SBOM-level nixpkgs metadata source export."""

import json
import uuid
from types import SimpleNamespace

import pandas as pd

from sbomnix import meta as sbomnix_meta
from sbomnix import meta_source as sbomnix_meta_source
from sbomnix.builder import SbomBuilder

_NAMES = ["hello-2.12.3"]


def _make_minimal_sbom(source):
    sbomdb = object.__new__(SbomBuilder)
    sbomdb.uid = "store_path"
    sbomdb.nix_path = "/nix/store/target"
    sbomdb.buildtime = False
    sbomdb.target_deriver = "/nix/store/target.drv"
    sbomdb.target_component_ref = "/nix/store/target.drv"
    sbomdb.depth = None
    sbomdb.uuid = uuid.uuid4()
    sbomdb.sbom_type = "runtime_only"
    sbomdb.nixpkgs_meta_source = source
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


def test_cdx_document_records_live_flake_meta_source(monkeypatch):
    source_path = "/nix/store/root-source"
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(
                returncode=0, stdout="/nix/store/abc-nixpkgs-src", stderr=""
            )
        if cmd == ["nix", "flake", "metadata", "/flake", "--json"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc"},
                    }
                ),
                returncode=0,
            )
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: fake_df,
    )
    monkeypatch.setattr(
        SbomBuilder, "lookup_dependencies", lambda *_args, **_kwargs: None
    )

    _df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref="/flake#nixosConfigurations.host.config.system.build.toplevel",
        original_ref="/flake#nixosConfigurations.host.config.system.build.toplevel",
        store_names=_NAMES,
    )
    sbomdb = _make_minimal_sbom(source)

    cdx = sbomdb.to_cdx_data()

    properties = {prop["name"]: prop["value"] for prop in cdx["metadata"]["properties"]}
    assert properties["nixpkgs:metadata_source_method"] == "flake-meta"
    assert properties["nixpkgs:path"] == "/nix/store/abc-nixpkgs-src"
    assert (
        properties["nixpkgs:flakeref"] == '/flake#nixosConfigurations."host".pkgs.path'
    )
    assert (
        properties["nixpkgs:message"]
        == "Scanning evaluated NixOS package set from flakeref"
    )
    assert "nixpkgs:rev" not in properties
    assert "nixpkgs:version" not in properties


def test_spdx_document_records_locked_nixpkgs_input(monkeypatch):
    source_path = "/nix/store/abc-src"
    nixpkgs_rev = "overriderev"
    fake_df = SimpleNamespace(empty=False)

    lock_graph = {
        "root": "root",
        "version": 7,
        "nodes": {
            "root": {"inputs": {"nixpkgs": ["nixpkgs", "nixpkgs_3"]}},
            "nixpkgs": {
                "locked": {
                    "type": "github",
                    "owner": "NixOS",
                    "repo": "nixpkgs",
                    "rev": "wrong-rev",
                }
            },
            "nixpkgs_3": {
                "locked": {
                    "type": "github",
                    "owner": "NixOS",
                    "repo": "nixpkgs",
                    "rev": nixpkgs_rev,
                }
            },
        },
    }

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc"},
                        "locks": lock_graph,
                    }
                ),
                returncode=0,
            )
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: fake_df,
    )
    monkeypatch.setattr(
        SbomBuilder, "lookup_dependencies", lambda *_args, **_kwargs: None
    )

    _df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".",
        original_ref=".",
        store_names=_NAMES,
    )
    sbomdb = _make_minimal_sbom(source)

    spdx = sbomdb.to_spdx_data()

    assert "included dependencies: 'runtime_only'" in spdx["comment"]
    assert (
        "nixpkgs metadata source: metadata_source_method=flake-meta" in spdx["comment"]
    )
    assert f"flakeref=github:NixOS/nixpkgs?rev={nixpkgs_rev}" in spdx["comment"]
    assert f"rev={nixpkgs_rev}" in spdx["comment"]
    assert "warning=" not in spdx["comment"]
