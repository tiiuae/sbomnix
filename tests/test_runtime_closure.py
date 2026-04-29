#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for structured runtime closure parsing."""

import subprocess

import pytest

from common.errors import InvalidNixJsonError, NixCommandError
from sbomnix import runtime as sbomnix_runtime
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


def test_runtime_closure_from_path_info_rejects_missing_references():
    with pytest.raises(InvalidNixJsonError, match="missing `references`"):
        runtime_closure_from_path_info(
            {
                "/nix/store/11111111111111111111111111111111-target-1.0": {
                    "deriver": None,
                }
            }
        )


def test_runtime_closure_from_path_info_rejects_malformed_reference_items():
    with pytest.raises(InvalidNixJsonError, match=r"references\[0\]"):
        runtime_closure_from_path_info(
            {
                "/nix/store/11111111111111111111111111111111-target-1.0": {
                    "references": [None],
                }
            }
        )


def test_load_runtime_closure_wraps_nix_command_failures(monkeypatch):
    def fail_exec_cmd(cmd):
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=cmd,
            stderr="unsupported path-info json format",
        )

    monkeypatch.setattr(sbomnix_runtime, "exec_cmd", fail_exec_cmd)

    with pytest.raises(NixCommandError, match="unsupported path-info json format"):
        sbomnix_runtime.load_runtime_closure(
            "/nix/store/11111111111111111111111111111111-target-1.0"
        )
