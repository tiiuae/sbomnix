#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-function-docstring,protected-access

"""Unit tests for derivation loading and SPDX hardening."""

import json
from collections import namedtuple
from types import SimpleNamespace

from common import spdx as common_spdx
from sbomnix import cdx as sbomnix_cdx
from sbomnix import derivation as sbomnix_derivation
from sbomnix import exporters as sbomnix_exporters


def test_load_derivation_uses_nix_derivation_show(monkeypatch):
    drv_path = "/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-2.12.3.drv"
    out_path = "/nix/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-hello-2.12.3"
    doc_path = "/nix/store/2ccccccccccccccccccccccccccccccc-hello-2.12.3-doc"
    calls = []

    def fake_nix_cmd(*args):
        return ["nix", *args]

    def fake_exec_cmd(cmd, **_kwargs):
        calls.append(cmd)
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "version": 4,
                    "derivations": {
                        drv_path: {
                            "name": "hello-2.12.3",
                            "version": 4,
                            "system": "x86_64-linux",
                            "outputs": {
                                "doc": {"path": doc_path},
                                "out": {"path": out_path},
                            },
                            "env": {
                                "name": "hello-2.12.3",
                                "pname": "hello",
                                "out": out_path,
                                "outputs": "out doc",
                                "version": "2.12.3",
                                "urls": "https://example.test/hello.tar.gz",
                            },
                        }
                    },
                }
            )
        )

    monkeypatch.setattr(sbomnix_derivation, "nix_cmd", fake_nix_cmd)
    monkeypatch.setattr(sbomnix_derivation, "exec_cmd", fake_exec_cmd)

    drv = sbomnix_derivation.load(drv_path, None)

    assert calls == [["nix", "derivation", "show", drv_path]]
    assert drv.store_path == drv_path
    assert drv.name == "hello-2.12.3"
    assert drv.pname == "hello"
    assert drv.version == "2.12.3"
    assert drv.system == "x86_64-linux"
    assert drv.out == out_path
    assert drv.outputs == [out_path, doc_path]
    assert drv.urls == "https://example.test/hello.tar.gz"
    assert drv.purl == "pkg:nix/hello@2.12.3"


def test_canonicalize_spdx_license_id_canonicalizes_aliases():
    expected_canonical_ids = {
        "GPL-2.0+": "GPL-2.0-or-later",
        "GPL-3.0": "GPL-3.0-only",
        "GPL-3.0+": "GPL-3.0-or-later",
        "LGPL-2.1": "LGPL-2.1-only",
        "LGPL-2.1+": "LGPL-2.1-or-later",
    }
    for license_id, canonical_id in expected_canonical_ids.items():
        assert common_spdx.canonicalize_spdx_license_id(license_id) == canonical_id
    assert (
        common_spdx.canonicalize_spdx_license_id("LicenseRef-scancode-free-unknown")
        == "LicenseRef-scancode-free-unknown"
    )
    assert common_spdx.canonicalize_spdx_license_id("MIT AND Apache-2.0") is None
    assert common_spdx.canonicalize_spdx_license_id("not-a-license") is None


def test_cdx_and_spdx_license_exporters_use_canonical_spdx_ids():
    drv_type = namedtuple(
        "Drv",
        [
            "name",
            "pname",
            "version",
            "purl",
            "cpe",
            "meta_description",
            "meta_license_spdxid",
            "meta_license_short",
            "patches",
            "outputs",
            "store_path",
            "out",
            "urls",
            "meta_homepage",
            "meta_position",
        ],
    )
    drv = drv_type(
        name="hello-2.12.3",
        pname="hello",
        version="2.12.3",
        purl="pkg:nix/hello@2.12.3",
        cpe="",
        meta_description="Hello",
        meta_license_spdxid=(
            "GPL-3.0;GPL-3.0+;LGPL-2.1;LGPL-2.1+;LicenseRef-scancode-free-unknown"
        ),
        meta_license_short="GPL2+",
        patches="",
        outputs=["/nix/store/out"],
        store_path="/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-2.12.3.drv",
        out="/nix/store/out",
        urls="",
        meta_homepage="",
        meta_position="",
    )

    component = sbomnix_cdx._drv_to_cdx_component(drv)
    package = sbomnix_exporters._drv_to_spdx_package(drv)

    assert component["licenses"] == [
        {"license": {"id": "GPL-3.0-only"}},
        {"license": {"id": "GPL-3.0-or-later"}},
        {"license": {"id": "LGPL-2.1-only"}},
        {"license": {"id": "LGPL-2.1-or-later"}},
        {"license": {"id": "LicenseRef-scancode-free-unknown"}},
    ]
    assert package["licenseInfoFromFiles"] == [
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LicenseRef-scancode-free-unknown",
    ]


def test_cdx_falls_back_to_license_short_name_when_spdx_id_is_invalid():
    drv_type = namedtuple(
        "Drv",
        [
            "name",
            "pname",
            "version",
            "purl",
            "cpe",
            "meta_description",
            "meta_license_spdxid",
            "meta_license_short",
            "patches",
            "outputs",
            "store_path",
            "out",
            "urls",
            "meta_homepage",
            "meta_position",
        ],
    )
    drv = drv_type(
        name="hello-2.12.3",
        pname="hello",
        version="2.12.3",
        purl="pkg:nix/hello@2.12.3",
        cpe="",
        meta_description="Hello",
        meta_license_spdxid="not-a-license",
        meta_license_short="Custom Short Name",
        patches="",
        outputs=["/nix/store/out"],
        store_path="/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-2.12.3.drv",
        out="/nix/store/out",
        urls="",
        meta_homepage="",
        meta_position="",
    )

    component = sbomnix_cdx._drv_to_cdx_component(drv)
    package = sbomnix_exporters._drv_to_spdx_package(drv)

    assert component["licenses"] == [{"license": {"name": "Custom Short Name"}}]
    assert "licenseInfoFromFiles" not in package
    assert package["licenseConcluded"] == "NOASSERTION"
