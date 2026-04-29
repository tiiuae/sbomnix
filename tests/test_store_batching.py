#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for batched store and derivation loading."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from common.errors import NixCommandError
from sbomnix import derivation as sbomnix_derivation


def test_load_many_batches_nix_derivation_show_and_preserves_outputs(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "derivations": {
                        "/nix/store/first.drv": {
                            "name": "first",
                            "env": {
                                "name": "first",
                                "pname": "first",
                                "version": "1.0",
                            },
                            "outputs": {
                                "out": {"path": "/nix/store/first-out"},
                            },
                        },
                        "/nix/store/second.drv": {
                            "name": "second",
                            "env": {
                                "name": "second",
                                "pname": "second",
                                "version": "2.0",
                            },
                            "outputs": {
                                "out": {"path": "/nix/store/second-out"},
                            },
                        },
                    },
                    "version": 4,
                }
            ),
            returncode=0,
            stderr="",
        )

    monkeypatch.setattr(sbomnix_derivation, "exec_cmd", fake_exec_cmd)

    loaded = sbomnix_derivation.load_many(
        ["/nix/store/first.drv", "/nix/store/second.drv"],
        output_paths_by_drv={
            "/nix/store/first.drv": {"/nix/store/first-extra-out"},
            "/nix/store/second.drv": {"/nix/store/second-extra-out"},
        },
        batch_size=50,
    )

    assert calls == [
        (
            [
                "nix",
                "derivation",
                "show",
                "/nix/store/first.drv",
                "/nix/store/second.drv",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
            ],
            {},
        )
    ]
    assert loaded["/nix/store/first.drv"].outputs == [
        "/nix/store/first-extra-out",
        "/nix/store/first-out",
    ]
    assert loaded["/nix/store/second.drv"].outputs == [
        "/nix/store/second-extra-out",
        "/nix/store/second-out",
    ]


def test_load_many_supports_output_path_queries(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "derivations": {
                        "/nix/store/canonical.drv": {
                            "name": "first",
                            "env": {
                                "name": "first",
                                "pname": "first",
                                "version": "1.0",
                            },
                            "outputs": {
                                "out": {"path": "/nix/store/first-out"},
                                "dev": {"path": "/nix/store/first-dev"},
                            },
                        },
                    },
                    "version": 4,
                }
            ),
            returncode=0,
            stderr="",
        )

    monkeypatch.setattr(sbomnix_derivation, "exec_cmd", fake_exec_cmd)

    loaded = sbomnix_derivation.load_many(
        ["/nix/store/first-out"],
        output_paths_by_drv={
            "/nix/store/first-out": {"/nix/store/first-out"},
        },
        batch_size=50,
    )

    assert calls == [
        (
            [
                "nix",
                "derivation",
                "show",
                "/nix/store/first-out",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
            ],
            {},
        )
    ]
    assert list(loaded) == ["/nix/store/canonical.drv"]
    assert loaded["/nix/store/canonical.drv"].store_path == "/nix/store/canonical.drv"
    assert loaded["/nix/store/canonical.drv"].outputs == [
        "/nix/store/first-dev",
        "/nix/store/first-out",
    ]


def test_load_many_maps_output_queries_from_derivation_env(monkeypatch):
    def fake_exec_cmd(cmd, **kwargs):
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "derivations": {
                        "/nix/store/fixed.drv": {
                            "name": "fixed",
                            "env": {
                                "name": "fixed",
                                "out": "/nix/store/fixed-out",
                                "outputs": "out",
                                "pname": "fixed",
                                "version": "1.0",
                            },
                            "outputs": {
                                "out": {
                                    "hash": "sha256-test",
                                    "method": "flat",
                                },
                            },
                        },
                    },
                    "version": 4,
                }
            ),
            returncode=0,
            stderr="",
        )

    monkeypatch.setattr(sbomnix_derivation, "exec_cmd", fake_exec_cmd)

    loaded = sbomnix_derivation.load_many(
        ["/nix/store/fixed-out"],
        output_paths_by_drv={
            "/nix/store/fixed-out": {"/nix/store/fixed-out"},
        },
        batch_size=50,
    )

    assert list(loaded) == ["/nix/store/fixed.drv"]
    assert loaded["/nix/store/fixed.drv"].outputs == ["/nix/store/fixed-out"]


def test_load_many_can_ignore_missing_output_derivations(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        query_paths = cmd[3:-4]
        if "/nix/store/missing-out" in query_paths:
            assert kwargs == {"raise_on_error": False, "log_error": False}
            return None
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "derivations": {
                        "/nix/store/good.drv": {
                            "name": "good",
                            "env": {
                                "name": "good",
                                "pname": "good",
                                "version": "1.0",
                            },
                            "outputs": {
                                "out": {"path": "/nix/store/good-out"},
                            },
                        },
                    },
                    "version": 4,
                }
            ),
            returncode=0,
            stderr="",
        )

    monkeypatch.setattr(sbomnix_derivation, "exec_cmd", fake_exec_cmd)

    loaded = sbomnix_derivation.load_many(
        ["/nix/store/good-out", "/nix/store/missing-out"],
        output_paths_by_drv={
            "/nix/store/good-out": {"/nix/store/good-out"},
            "/nix/store/missing-out": {"/nix/store/missing-out"},
        },
        batch_size=50,
        ignore_missing=True,
    )

    assert list(loaded) == ["/nix/store/good.drv"]
    assert [call[0][3:-4] for call in calls] == [
        ["/nix/store/good-out", "/nix/store/missing-out"],
        ["/nix/store/good-out"],
        ["/nix/store/missing-out"],
    ]


def test_load_recursive_wraps_nix_command_failures(monkeypatch):
    def fail_exec_cmd(cmd):
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=cmd,
            stderr="recursive derivation show failed",
        )

    monkeypatch.setattr(sbomnix_derivation, "exec_cmd", fail_exec_cmd)

    with pytest.raises(NixCommandError, match="recursive derivation show failed"):
        sbomnix_derivation.load_recursive(
            "/nix/store/11111111111111111111111111111111-target-1.0.drv"
        )


def test_load_rejects_empty_derivation_metadata(monkeypatch):
    monkeypatch.setattr(
        sbomnix_derivation,
        "exec_cmd",
        lambda _cmd: SimpleNamespace(stdout="{}", stderr="", returncode=0),
    )

    with pytest.raises(NixCommandError, match="No derivation metadata returned"):
        sbomnix_derivation.load(
            "/nix/store/11111111111111111111111111111111-target-1.0",
            None,
        )


def test_load_recursive_rejects_empty_derivation_metadata(monkeypatch):
    monkeypatch.setattr(
        sbomnix_derivation,
        "exec_cmd",
        lambda _cmd: SimpleNamespace(stdout="{}", stderr="", returncode=0),
    )

    with pytest.raises(NixCommandError, match="No derivation metadata returned"):
        sbomnix_derivation.load_recursive(
            "/nix/store/11111111111111111111111111111111-target-1.0.drv"
        )
