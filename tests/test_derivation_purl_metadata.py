# SPDX-FileCopyrightText: 2026 Tanishq Palandurkar
# SPDX-License-Identifier: Apache-2.0

"""Explicit derivation identifiers must take precedence over name heuristics."""

import json

import pytest

from common.nix_utils import parse_nix_derivation_show
from sbomnix.derivation import Derive
from sbomnix.exporters import _drv_to_spdx_extrefs


def load_component(meta, name="bash-5.3p9", pname="bash", version="5.3p9"):
    """Exercise the real JSON normalization and component reader together."""
    path = "/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test.drv"
    payload = {
        "version": 4,
        "derivations": {
            path: {
                "name": name,
                "system": "aarch64-darwin",
                "outputs": {
                    "out": {"path": "/nix/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-test"}
                },
                "structuredAttrs": {"pname": pname, "version": version},
                "meta": meta,
            }
        },
    }
    info = parse_nix_derivation_show(json.dumps(payload))[path]
    return Derive.from_nix_derivation_info(path, info)


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
