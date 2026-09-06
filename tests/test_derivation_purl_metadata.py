# SPDX-FileCopyrightText: 2026 Tanishq Palandurkar
# SPDX-License-Identifier: Apache-2.0

"""Explicit derivation identifiers must take precedence over name heuristics."""

import json
import subprocess

import pytest

from common.nix_utils import parse_nix_derivation_show
from sbomnix import builder as builder_module
from sbomnix import derivation as derivation_module
from sbomnix.builder import SbomBuilder
from sbomnix.closure import dependency_rows_to_dataframe
from sbomnix.derivation import Derive
from sbomnix.exporters import (
    _drv_to_spdx_extrefs,
    build_cdx_document,
    build_spdx_document,
)
from sbomnix.runtime import RuntimeClosure

DRV_PATH = "/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test.drv"
OUT_PATH = "/nix/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-test"


def derivation_payload(meta, name="bash-5.3p9", pname="bash", version="5.3p9"):
    """Return modern derivation JSON with an offline, dependency-free target."""
    return {
        "version": 4,
        "derivations": {
            DRV_PATH: {
                "name": name,
                "system": "aarch64-darwin",
                "outputs": {"out": {"path": OUT_PATH}},
                "inputs": {"drvs": {}, "srcs": []},
                "structuredAttrs": {"pname": pname, "version": version},
                "meta": meta,
            }
        },
    }


def load_component(meta, name="bash-5.3p9", pname="bash", version="5.3p9"):
    """Exercise the real JSON normalization and component reader together."""
    payload = derivation_payload(meta, name, pname, version)
    info = parse_nix_derivation_show(json.dumps(payload))[DRV_PATH]
    return Derive.from_nix_derivation_info(DRV_PATH, info)


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:github/NixOS/nixpkgs@v1.0", "pkg:github/nixos/nixpkgs@v1.0"),
        (
            "pkg:generic/repo?vcs_url=https://host/owner/repo@rev",
            "pkg:generic/repo?vcs_url=https://host/owner/repo%40rev",
        ),
        (
            "pkg:maven/org.Example/MyLibrary@ReleaseA",
            "pkg:maven/org.Example/MyLibrary@ReleaseA",
        ),
    ],
)
def test_metadata_purl_is_normalized_by_package_type(purl, expected):
    assert load_component({"identifiers": {"purl": purl}}).purl == expected


@pytest.mark.parametrize("buildtime", [True, False])
@pytest.mark.parametrize("include_meta", [True, False])
@pytest.mark.parametrize("pname", ["bash", "source"])
def test_metadata_policy_reaches_both_exporters(
    monkeypatch, buildtime, include_meta, pname
):
    """Catch ignored opt-outs and PURLs lost in the production dataframe path."""
    payload = derivation_payload(
        {"identifiers": {"purl": "pkg:github/NixOS/nixpkgs@v1.0"}},
        name="source" if pname == "source" else "bash-5.3p9",
        pname=pname,
    )
    # Replace only external Nix operations; keep parsing, component assembly,
    # metadata-source selection and both document exporters real.
    monkeypatch.setattr(
        derivation_module,
        "exec_cmd",
        lambda cmd, **_kwargs: subprocess.CompletedProcess(
            cmd, 0, stdout=json.dumps(payload)
        ),
    )
    monkeypatch.setattr(builder_module, "require_deriver", lambda _path: DRV_PATH)
    monkeypatch.setattr(builder_module, "find_deriver", lambda _path: DRV_PATH)
    monkeypatch.setattr(builder_module, "is_loadable_deriver_path", lambda _path: True)
    monkeypatch.setattr(
        builder_module,
        "load_runtime_closure",
        lambda _path: RuntimeClosure(
            df_deps=dependency_rows_to_dataframe([]),
            output_paths_by_drv={DRV_PATH: {OUT_PATH}},
        ),
    )
    builder = SbomBuilder(
        OUT_PATH,
        buildtime=buildtime,
        include_meta=include_meta,
        include_cpe=False,
    )
    expected = "pkg:github/nixos/nixpkgs@v1.0"
    if not include_meta:
        expected = "" if pname == "source" else "pkg:nix/bash@5.3p9"
    assert builder.df_sbomdb.iloc[0]["purl"] == expected
    cdx = build_cdx_document(builder)
    spdx = build_spdx_document(builder)
    assert cdx["metadata"]["component"].get("purl", "") == expected
    refs = spdx["packages"][0].get("externalRefs", [])
    purls = [ref["referenceLocator"] for ref in refs if ref["referenceType"] == "purl"]
    assert purls == ([expected] if expected else [])


def test_explicit_attribute_identifier_overrides_reconstructed_name():
    purl = "pkg:nix/nixpkgs/bashNonInteractive@5.3p9?output=out"
    drv = load_component({"identifiers": {"purl": purl}})
    assert drv.purl == purl
    assert drv.pname == "bash"
    assert drv.version == "5.3p9"


def test_explicit_source_identifier_is_not_suppressed():
    drv = load_component(
        {"identifiers": {"purl": "pkg:github/example/project@v1.0"}},
        name="source",
        pname="source",
        version="",
    )
    assert drv.purl == "pkg:github/example/project@v1.0"


def test_spdx_reference_preserves_explicit_purl():
    drv = load_component({"identifiers": {"purl": "pkg:nix/nixpkgs/bash@5.3p9"}})
    assert _drv_to_spdx_extrefs(drv) == [
        {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": "pkg:nix/nixpkgs/bash@5.3p9",
        }
    ]


@pytest.mark.parametrize(
    "meta",
    [
        None,
        {},
        "bad",
        {"identifiers": None},
        {"identifiers": {}},
        {"identifiers": {"purl": None}},
        {"identifiers": {"purl": ""}},
        {"identifiers": {"purl": 123}},
        {"identifiers": {"purl": "not-a-purl"}},
    ],
)
def test_missing_or_invalid_metadata_retains_existing_fallback(meta):
    assert load_component(meta).purl == "pkg:nix/bash@5.3p9"


def test_source_without_identifier_still_has_no_invented_purl():
    assert load_component({}, name="source", pname="source", version="").purl == ""


@pytest.mark.parametrize(
    "purl", ["pkg:github/example/project", "pkg:github/example/project@release-tag"]
)
def test_explicit_identifier_version_is_not_replaced_with_derivation_version(purl):
    drv = load_component({"identifiers": {"purl": purl}})
    assert drv.purl == purl
    assert drv.version == "5.3p9"


def test_plural_identifiers_alone_retain_existing_fallback():
    drv = load_component(
        {"identifiers": {"purls": ["pkg:github/example/project@release-tag"]}}
    )
    assert drv.purl == "pkg:nix/bash@5.3p9"


@pytest.mark.parametrize("batch_fallback", [False, True])
def test_single_derivation_load_honors_metadata_opt_out(monkeypatch, batch_fallback):
    payload = derivation_payload(
        {"identifiers": {"purl": "pkg:github/example/project@release-tag"}}
    )
    replies = [json.dumps(payload)]
    if batch_fallback:
        replies.insert(0, json.dumps({"version": 4, "derivations": {}}))
    responses = iter(replies)
    monkeypatch.setattr(
        derivation_module,
        "exec_cmd",
        lambda cmd, **_kwargs: subprocess.CompletedProcess(
            cmd, 0, stdout=next(responses)
        ),
    )
    if batch_fallback:
        drv = derivation_module.load_many([DRV_PATH], include_meta=False)[DRV_PATH]
    else:
        drv = derivation_module.load(DRV_PATH, None, include_meta=False)
    assert drv.purl == "pkg:nix/bash@5.3p9"
