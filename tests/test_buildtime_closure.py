#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for recursive build-time derivation parsing."""

import pytest

from common.errors import InvalidNixJsonError
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
                },
                "srcs": [
                    "/nix/store/44444444444444444444444444444444-builder.sh",
                ],
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
        {
            "src_path": "/nix/store/44444444444444444444444444444444-builder.sh",
            "src_pname": "builder.sh",
            "target_path": "/nix/store/11111111111111111111111111111111-target-1.0.drv",
            "target_pname": "target-1.0.drv",
        },
    ]


def test_recursive_buildtime_dependencies_df_rejects_legacy_input_drvs():
    drv_infos = {
        "/nix/store/11111111111111111111111111111111-target-1.0.drv": {
            "inputDrvs": {
                "/nix/store/22222222222222222222222222222222-dep-a-1.0.drv": ["out"],
            }
        }
    }

    with pytest.raises(InvalidNixJsonError, match="unsupported legacy `inputDrvs`"):
        derivation_dependencies_df(drv_infos)


def test_recursive_buildtime_dependencies_df_rejects_missing_input_schema():
    drv_infos = {
        "/nix/store/11111111111111111111111111111111-target-1.0.drv": {
            "name": "target-1.0",
        }
    }

    with pytest.raises(InvalidNixJsonError, match="missing derivation inputs"):
        derivation_dependencies_df(drv_infos)


def test_recursive_buildtime_dependencies_df_accepts_empty_modern_inputs():
    drv_infos = {
        "/nix/store/11111111111111111111111111111111-leaf-1.0.drv": {
            "inputs": {
                "drvs": {},
                "srcs": [],
            }
        }
    }

    df = derivation_dependencies_df(drv_infos)

    assert df.empty
    assert list(df.columns) == [
        "src_path",
        "src_pname",
        "target_path",
        "target_pname",
    ]


def test_recursive_buildtime_dependencies_df_rejects_missing_source_inputs():
    drv_infos = {
        "/nix/store/11111111111111111111111111111111-target-1.0.drv": {
            "inputs": {
                "drvs": {},
            }
        }
    }

    with pytest.raises(InvalidNixJsonError, match="missing `inputs.srcs`"):
        derivation_dependencies_df(drv_infos)


def test_recursive_buildtime_dependencies_df_rejects_missing_derivation_inputs():
    drv_infos = {
        "/nix/store/11111111111111111111111111111111-target-1.0.drv": {
            "inputs": {
                "srcs": [],
            }
        }
    }

    with pytest.raises(InvalidNixJsonError, match="missing `inputs.drvs`"):
        derivation_dependencies_df(drv_infos)
