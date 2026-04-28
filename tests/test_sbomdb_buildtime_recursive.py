#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for recursive build-time derivation parsing."""

from sbomnix.closure import derivation_dependencies_df


def test_recursive_buildtime_dependencies_df_reads_new_derivation_inputs():
    drv_infos = {
        "/nix/store/11111111111111111111111111111111-target-1.0.drv": {
            "inputs": {
                "drvs": {
                    "/nix/store/22222222222222222222222222222222-dep-a-1.0.drv": [
                        "out"
                    ],
                    "/nix/store/33333333333333333333333333333333-dep-b-1.0.drv": [
                        "out"
                    ],
                }
            }
        }
    }

    df = derivation_dependencies_df(drv_infos)
    rows = df.sort_values("src_path").to_dict("records")

    assert rows == [
        {
            "src_path": "/nix/store/22222222222222222222222222222222-dep-a-1.0.drv",
            "src_pname": "dep-a-1.0.drv",
            "target_path": "/nix/store/11111111111111111111111111111111-target-1.0.drv",
            "target_pname": "target-1.0.drv",
        },
        {
            "src_path": "/nix/store/33333333333333333333333333333333-dep-b-1.0.drv",
            "src_pname": "dep-b-1.0.drv",
            "target_path": "/nix/store/11111111111111111111111111111111-target-1.0.drv",
            "target_pname": "target-1.0.drv",
        },
    ]


def test_recursive_buildtime_dependencies_df_reads_legacy_input_drvs():
    drv_infos = {
        "/nix/store/11111111111111111111111111111111-target-1.0.drv": {
            "inputDrvs": {
                "/nix/store/22222222222222222222222222222222-dep-a-1.0.drv": ["out"],
            }
        }
    }

    df = derivation_dependencies_df(drv_infos)

    assert df.to_dict("records") == [
        {
            "src_path": "/nix/store/22222222222222222222222222222222-dep-a-1.0.drv",
            "src_pname": "dep-a-1.0.drv",
            "target_path": "/nix/store/11111111111111111111111111111111-target-1.0.drv",
            "target_pname": "target-1.0.drv",
        }
    ]
