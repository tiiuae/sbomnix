#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Whitespace-safe argv construction tests for nix-facing helpers."""

import json
from types import SimpleNamespace

import pytest

from common.proc import exec_cmd, nix_cmd
from nixmeta import flake_metadata
from nixupdate import nix_outdated
from sbomnix import nix as sbomnix_nix
from sbomnix.meta import Meta


def test_exec_cmd_rejects_string_commands():
    with pytest.raises(
        TypeError,
        match="cmd must be an argv sequence, not a string-like value",
    ):
        exec_cmd("echo hello")


def test_find_deriver_uses_argv_list(monkeypatch):
    calls = []
    drv_basename = "my target.drv"

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        if cmd[:3] == ["nix", "derivation", "show"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "derivations": {
                            drv_basename: {"name": "target"},
                        },
                        "version": 4,
                    }
                ),
                returncode=0,
                stderr="",
            )
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(sbomnix_nix, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr("os.path.exists", lambda path: path.endswith(".drv"))

    drv_path = sbomnix_nix.find_deriver("/nix/store/my target")

    assert drv_path == "my target.drv"
    assert calls == [
        (
            [
                "nix",
                "derivation",
                "show",
                "/nix/store/my target",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
            ],
            {"raise_on_error": False, "log_error": False},
        ),
    ]


def test_find_deriver_supports_nix_2_33_wrapped_json(monkeypatch):
    target_path = "/custom/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root"
    drv_basename = "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-root.drv"

    def fake_exec_cmd(cmd, **kwargs):
        if cmd[:3] == ["nix", "derivation", "show"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "derivations": {drv_basename: {"name": "root"}},
                        "version": 4,
                    }
                ),
                returncode=0,
                stderr="",
            )
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(sbomnix_nix, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr("os.path.exists", lambda path: path.endswith(".drv"))

    drv_path = sbomnix_nix.find_deriver(target_path)

    assert drv_path == f"/custom/store/{drv_basename}"


def test_get_flake_metadata_uses_argv_list():
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout='{"path": "/nix/store/nixpkgs"}', returncode=0)

    meta = flake_metadata.get_flake_metadata(
        "/tmp/my flake",
        exec_cmd_fn=fake_exec_cmd,
        nix_cmd_fn=nix_cmd,
    )

    assert meta == {"path": "/nix/store/nixpkgs"}
    assert calls == [
        (
            [
                "nix",
                "flake",
                "metadata",
                "/tmp/my flake",
                "--json",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
            ],
            {"raise_on_error": False, "return_error": True, "log_error": False},
        )
    ]


def test_get_flake_metadata_strips_nixpkgs_prefix_without_splitting_spaces():
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout='{"path": "/nix/store/nixpkgs"}', returncode=0)

    flake_metadata.get_flake_metadata(
        "nixpkgs=/tmp/my flake",
        exec_cmd_fn=fake_exec_cmd,
        nix_cmd_fn=nix_cmd,
    )

    assert calls[0][0][3] == "/tmp/my flake"


def test_run_nix_visualize_uses_argv_list(tmp_path, monkeypatch):
    calls = []
    output_path = tmp_path / "graph output.csv"

    class FakeTempFile:
        """Minimal context manager compatible with NamedTemporaryFile."""

        def __init__(self, path):
            self.name = path.as_posix()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(
        nix_outdated,
        "NamedTemporaryFile",
        lambda **_kwargs: FakeTempFile(output_path),
    )
    monkeypatch.setattr(nix_outdated, "exec_cmd", fake_exec_cmd)

    returned_path = nix_outdated._run_nix_visualize("/nix/store/my target")

    assert returned_path == output_path
    assert calls == [
        (
            [
                "nix-visualize",
                f"--output={output_path.as_posix()}",
                "/nix/store/my target",
            ],
            {},
        )
    ]


def test_meta_reads_nix_path_entry_with_spaces(monkeypatch):
    scanned = []

    monkeypatch.setenv("NIX_PATH", "foo=/tmp/other:nixpkgs=/tmp/my flake")
    monkeypatch.setattr(Meta, "_scan", lambda self, path: scanned.append(path) or path)

    resolved = Meta().get_nixpkgs_meta()

    assert resolved == "/tmp/my flake"
    assert scanned == ["/tmp/my flake"]
