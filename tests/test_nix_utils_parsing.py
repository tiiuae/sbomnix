#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for nix derivation JSON normalization helpers."""

import json

from common.nix_utils import get_nix_store_dir, parse_nix_derivation_show


def test_parse_nix_derivation_show_normalizes_nix_2_33_store_paths():
    parsed = parse_nix_derivation_show(
        json.dumps(
            {
                "version": 4,
                "derivations": {
                    "0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv": {
                        "name": "root",
                        "outputs": {
                            "out": {
                                "path": "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-root",
                            }
                        },
                    }
                },
            }
        ),
        store_path_hint="/custom/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv",
    )

    assert parsed == {
        "/custom/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv": {
            "name": "root",
            "outputs": {
                "out": {
                    "path": "/custom/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-root",
                }
            },
        }
    }


def test_get_nix_store_dir_ignores_colon_separated_env_paths():
    assert (
        get_nix_store_dir(
            "/custom/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bin:"
            "/custom/store/2ccccccccccccccccccccccccccccccc-sbin"
        )
        == "/custom/store"
    )


def test_parse_nix_derivation_show_infers_store_dir_from_path_like_env_values():
    drv_basename = "0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    out_basename = "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-root"

    parsed = parse_nix_derivation_show(
        json.dumps(
            {
                "version": 4,
                "derivations": {
                    drv_basename: {
                        "name": "root",
                        "outputs": {"out": {"method": "nar"}},
                        "env": {
                            "out": out_basename,
                            "PATH": (
                                "/custom/store/3ddddddddddddddddddddddddddddddd-coreutils/bin:"
                                "/custom/store/4eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-git/bin:"
                                "/custom/store/5fffffffffffffffffffffffffffffff-graphviz/bin"
                            ),
                        },
                    }
                },
            }
        )
    )

    drv_path = f"/custom/store/{drv_basename}"
    assert list(parsed) == [drv_path]
    assert parsed[drv_path]["env"]["out"] == f"/custom/store/{out_basename}"
