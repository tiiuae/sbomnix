#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for Repology SBOM helpers."""

import json

import pandas as pd

from repology.sbom import (
    is_ignored_sbom_package,
    make_sbom_status_row,
    merge_sbom_fields,
    parse_cdx_sbom,
    sbom_row_classify,
)


def test_parse_cdx_sbom_normalizes_names_and_includes_metadata_component(tmp_path):
    sbom_path = tmp_path / "sbom.cdx.json"
    sbom_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "component": {"name": "libtiff", "version": "4.6.0"},
                },
                "components": [
                    {"name": "python311-requests", "version": "2.32.0"},
                ],
            }
        ),
        encoding="utf-8",
    )

    df = parse_cdx_sbom(sbom_path)

    assert df.to_dict("records") == [
        {"name": "python:requests", "version": "2.32.0"},
        {"name": "tiff", "version": "4.6.0"},
    ]


def test_merge_sbom_fields_and_classify_outdated_versions():
    df_sbom = pd.DataFrame([{"name": "hello", "version": "2.10"}])
    df_repo = pd.DataFrame(
        [
            {
                "repo": "nix_unstable",
                "package": "hello",
                "version": "2.11",
                "status": "newest",
                "potentially_vulnerable": "0",
                "newest_upstream_release": "2.12",
            }
        ]
    )

    df = merge_sbom_fields(df_sbom, df_repo)
    df["sbom_version_classify"] = df.apply(sbom_row_classify, axis=1)

    assert df["version_sbom"].tolist() == ["2.10"]
    assert df["sbom_version_classify"].tolist() == ["sbom_pkg_needs_update"]


def test_sbom_status_helpers_cover_ignored_rows():
    assert is_ignored_sbom_package("archive.tar.gz") is True
    assert is_ignored_sbom_package("openssl") is False
    assert make_sbom_status_row("nix_unstable", "archive.tar.gz", "1.0", "IGNORED") == {
        "repo": "nix_unstable",
        "package": "archive.tar.gz",
        "version": "1.0",
        "status": "IGNORED",
        "potentially_vulnerable": "",
        "newest_upstream_release": "",
    }
