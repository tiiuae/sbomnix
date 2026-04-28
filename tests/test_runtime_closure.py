#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for structured runtime closure parsing."""

from sbomnix.runtime import runtime_closure_from_path_info


def test_runtime_closure_from_path_info_extracts_edges_and_derivers():
    closure = runtime_closure_from_path_info(
        {
            "/nix/store/11111111111111111111111111111111-target-1.0": {
                "deriver": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-target-1.0.drv",
                "references": [
                    "/nix/store/11111111111111111111111111111111-target-1.0",
                    "/nix/store/22222222222222222222222222222222-dep-1.0",
                ],
            },
            "/nix/store/22222222222222222222222222222222-dep-1.0": {
                "deriver": "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-dep-1.0.drv",
                "references": ["/nix/store/22222222222222222222222222222222-dep-1.0"],
            },
        }
    )

    assert closure.df_deps.to_dict("records") == [
        {
            "src_path": "/nix/store/22222222222222222222222222222222-dep-1.0",
            "src_pname": "dep-1.0",
            "target_path": "/nix/store/11111111111111111111111111111111-target-1.0",
            "target_pname": "target-1.0",
        }
    ]
    assert closure.output_paths_by_drv == {
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-target-1.0.drv": {
            "/nix/store/11111111111111111111111111111111-target-1.0"
        },
        "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-dep-1.0.drv": {
            "/nix/store/22222222222222222222222222222222-dep-1.0"
        },
    }


def test_runtime_closure_from_path_info_supports_list_payloads():
    closure = runtime_closure_from_path_info(
        [
            {
                "path": "/nix/store/11111111111111111111111111111111-target-1.0",
                "deriver": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-target-1.0.drv",
                "references": [],
            }
        ]
    )

    assert closure.df_deps.empty
    assert closure.output_paths_by_drv == {
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-target-1.0.drv": {
            "/nix/store/11111111111111111111111111111111-target-1.0"
        }
    }
