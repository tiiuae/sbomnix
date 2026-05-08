#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for nixmeta parsing helpers."""

import json
from pathlib import Path
from types import SimpleNamespace

from nixmeta import metadata_json
from nixmeta import scanner as nixmeta_scanner
from nixmeta.resources import meta_nix_path

REPOROOT = Path(__file__).resolve().parent.parent


def test_parse_json_metadata_flattens_nested_fields(tmp_path):
    json_path = tmp_path / "meta.json"
    json_path.write_text(
        json.dumps(
            {
                "hello": {
                    "name": "hello-2.12.1",
                    "pname": "hello",
                    "version": "2.12.1",
                    "ambiguous": True,
                    "preciseNeeded": False,
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
            "meta_ambiguous": "True",
            "meta_precise_needed": "False",
            "meta_homepage": "https://example.invalid/hello",
            "meta_unfree": "False",
            "meta_description": "GNU hello",
            "meta_position": "pkgs/tools/misc/hello/default.nix:1",
            "meta_license_entries_json": '[{"fullName":null,"raw":null,"shortName":"GPLv3+","spdxId":"GPL-3.0-or-later"}]',
            "meta_license_short": "GPLv3+",
            "meta_license_spdxid": "GPL-3.0-or-later",
            "meta_maintainers_email": "maintainer@example.invalid",
        }
    ]


def test_parse_json_metadata_preserves_lossless_license_entries(tmp_path):
    json_path = tmp_path / "meta.json"
    json_path.write_text(
        json.dumps(
            {
                "mixed-license": {
                    "name": "mixed-license-1.0",
                    "pname": "mixed-license",
                    "version": "1.0",
                    "meta": {
                        "licenseEntries": [
                            {
                                "shortName": "MIT",
                                "spdxId": "MIT",
                                "fullName": "MIT License",
                                "raw": None,
                            },
                            {
                                "shortName": None,
                                "spdxId": None,
                                "fullName": "Public Domain",
                                "raw": None,
                            },
                            "Custom-Scalar-License",
                        ]
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    df = metadata_json.parse_json_metadata(json_path)
    row = df.to_dict(orient="records")[0]

    assert json.loads(row["meta_license_entries_json"]) == [
        {
            "spdxId": "MIT",
            "shortName": "MIT",
            "fullName": "MIT License",
            "raw": None,
        },
        {
            "spdxId": None,
            "shortName": None,
            "fullName": "Public Domain",
            "raw": None,
        },
        {
            "spdxId": None,
            "shortName": None,
            "fullName": None,
            "raw": "Custom-Scalar-License",
        },
    ]
    assert row["meta_license_short"] == "MIT"
    assert row["meta_license_spdxid"] == "MIT"


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


def test_meta_nix_path_points_to_packaged_helper():
    meta_nix = meta_nix_path()

    assert meta_nix.name == "meta.nix"
    assert meta_nix.is_file()
    assert "Look up nixpkgs metadata for a list of store-path names." in (
        meta_nix.read_text(encoding="utf-8")
    )


def test_pyproject_declares_meta_nix_as_package_data():
    pyproject = (REPOROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "[tool.setuptools.package-data]" in pyproject
    assert 'nixmeta = ["meta.nix"]' in pyproject
