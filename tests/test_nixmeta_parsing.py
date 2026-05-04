#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for nixmeta parsing helpers."""

import json
from types import SimpleNamespace

from nixmeta import metadata_json
from nixmeta import scanner as nixmeta_scanner


def test_parse_json_metadata_flattens_nested_fields(tmp_path):
    json_path = tmp_path / "meta.json"
    json_path.write_text(
        json.dumps(
            {
                "hello": {
                    "name": "hello-2.12.1",
                    "pname": "hello",
                    "version": "2.12.1",
                    "meta": {
                        "homepage": ["https://example.invalid/hello"],
                        "unfree": False,
                        "description": "GNU hello",
                        "position": "pkgs/tools/misc/hello/default.nix:1",
                        "license": [
                            {"shortName": "GPLv3+", "spdxId": "GPL-3.0-or-later"}
                        ],
                        "maintainers": [
                            {"email": "maintainer@example.invalid"},
                        ],
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    df = metadata_json.parse_json_metadata(json_path)

    assert df.to_dict(orient="records") == [
        {
            "name": "hello-2.12.1",
            "pname": "hello",
            "version": "2.12.1",
            "meta_homepage": "https://example.invalid/hello",
            "meta_unfree": "False",
            "meta_description": "GNU hello",
            "meta_position": "pkgs/tools/misc/hello/default.nix:1",
            "meta_license_short": "GPLv3+",
            "meta_license_spdxid": "GPL-3.0-or-later",
            "meta_maintainers_email": "maintainer@example.invalid",
        }
    ]


def test_scan_store_names_preserves_successful_empty_result(monkeypatch):
    """A successful meta.nix lookup with no matches must remain distinguishable."""
    monkeypatch.setattr(
        nixmeta_scanner,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(
        nixmeta_scanner,
        "exec_cmd",
        lambda cmd, **_kwargs: SimpleNamespace(returncode=0, stdout="{}", stderr=""),
    )

    scanner = nixmeta_scanner.NixMetaScanner()
    scanner.scan_store_names(["ghaf.iso"], pkgs_expr="pkgs")

    df = scanner.to_df()
    assert df is not None
    assert df.empty
    assert scanner.had_failures is False
