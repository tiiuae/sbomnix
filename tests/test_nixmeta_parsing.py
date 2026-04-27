#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-function-docstring

"""Focused tests for nixmeta parsing helpers."""

import json

from nixmeta import metadata_json


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
