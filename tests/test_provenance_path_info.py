#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for strict provenance path-info handling."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from common.errors import InvalidNixJsonError, NixCommandError
from common.nix_utils import normalize_nix_path_info
from provenance.dependencies import DependencyHooks, dependency_paths
from provenance.path_info import nar_hash_for_path, query_path_info


def test_normalize_path_info_rejects_malformed_list_records():
    with pytest.raises(InvalidNixJsonError, match="missing path string"):
        normalize_nix_path_info([{"narHash": "sha256-test"}])


def test_normalize_path_info_rejects_malformed_object_records():
    with pytest.raises(InvalidNixJsonError, match="expected path-info record"):
        normalize_nix_path_info({"/nix/store/target": None})


def test_normalize_path_info_supports_list_records():
    first = "/nix/store/11111111111111111111111111111111-first"
    second = "/nix/store/22222222222222222222222222222222-second"

    assert normalize_nix_path_info(
        [
            {"path": first, "references": []},
            {"storePath": second, "references": [first]},
        ]
    ) == {
        first: {"path": first, "references": []},
        second: {"storePath": second, "references": [first]},
    }


def test_nar_hash_for_path_rejects_missing_hash():
    with pytest.raises(InvalidNixJsonError, match="missing `narHash`"):
        nar_hash_for_path({"/nix/store/target": {}}, "/nix/store/target")


def test_nar_hash_for_path_rejects_missing_record():
    with pytest.raises(InvalidNixJsonError, match="missing path-info record"):
        nar_hash_for_path({}, "/nix/store/target")


def test_dependency_paths_rejects_mismatched_path_info_record():
    requested = "/nix/store/11111111111111111111111111111111-requested.drv"
    returned = "/nix/store/22222222222222222222222222222222-other.drv"

    def fake_exec_cmd(cmd, **_kwargs):
        return SimpleNamespace(stdout=json.dumps({returned: {"references": []}}))

    with pytest.raises(InvalidNixJsonError, match="missing path-info record"):
        dependency_paths(
            requested,
            hooks=DependencyHooks(exec_cmd_fn=fake_exec_cmd),
        )


def test_dependency_paths_recursive_includes_derivation_outputs():
    root_drv = "/nix/store/11111111111111111111111111111111-root.drv"
    dep_drv = "/nix/store/22222222222222222222222222222222-dependency.drv"
    root_out = "/nix/store/33333333333333333333333333333333-root"
    dep_out = "/nix/store/44444444444444444444444444444444-dependency"

    def fake_exec_cmd(cmd, **_kwargs):
        assert "--recursive" in cmd
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    root_drv: {"references": [dep_drv]},
                    dep_drv: {"references": []},
                }
            )
        )

    assert dependency_paths(
        root_drv,
        recursive=True,
        outputs_by_path={
            root_out: ({}, {}),
            dep_out: ({}, {}),
        },
        hooks=DependencyHooks(exec_cmd_fn=fake_exec_cmd),
    ) == [
        root_drv,
        dep_drv,
        root_out,
        dep_out,
    ]


def test_query_path_info_wraps_nix_command_failures():
    def fail_exec_cmd(cmd, **_kwargs):
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=cmd,
            stderr="unsupported path-info json format",
        )

    with pytest.raises(NixCommandError, match="unsupported path-info json format"):
        query_path_info(
            ["/nix/store/11111111111111111111111111111111-target-1.0"],
            exec_cmd_fn=fail_exec_cmd,
        )
