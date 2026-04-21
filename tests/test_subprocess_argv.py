#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

"""Unit tests for whitespace-safe subprocess argv construction."""

import json
from types import SimpleNamespace

import pytest

from common import utils
from nixmeta import scanner
from nixupdate import nix_outdated
from sbomnix import nix as sbomnix_nix
from sbomnix.meta import Meta
from vulnxscan.vulnscan import VulnScan


def test_try_resolve_flakeref_uses_argv_lists(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        if cmd[1] == "eval":
            return SimpleNamespace(stdout="/nix/store/resolved\n", returncode=0)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(utils, "exec_cmd", fake_exec_cmd)

    resolved = utils.try_resolve_flakeref(
        "/tmp/my flake#pkg", force_realise=True, impure=True
    )

    assert resolved == "/nix/store/resolved"
    assert calls == [
        (
            [
                "nix",
                "eval",
                "--raw",
                "/tmp/my flake#pkg",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
                "--impure",
            ],
            {"raise_on_error": False, "return_error": True, "log_error": False},
        ),
        (
            [
                "nix",
                "build",
                "--no-link",
                "/tmp/my flake#pkg",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
                "--impure",
            ],
            {"raise_on_error": False, "return_error": True, "log_error": False},
        ),
    ]


def test_try_resolve_flakeref_raises_on_failed_force_realise(monkeypatch):
    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1] == "eval":
            return SimpleNamespace(stdout="/nix/store/resolved\n", returncode=0)
        return SimpleNamespace(stdout="", stderr="build failed", returncode=1)

    monkeypatch.setattr(utils, "exec_cmd", fake_exec_cmd)

    with pytest.raises(utils.FlakeRefRealisationError, match="build failed"):
        utils.try_resolve_flakeref("/tmp/my flake#pkg", force_realise=True)


def test_try_resolve_flakeref_raises_on_failed_eval_for_flakeref(monkeypatch):
    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout="", stderr="attribute missing", returncode=1)

    monkeypatch.setattr(utils, "exec_cmd", fake_exec_cmd)

    with pytest.raises(utils.FlakeRefResolutionError, match="attribute missing"):
        utils.try_resolve_flakeref(".#missing")


def test_try_resolve_flakeref_returns_none_for_non_flake_path(monkeypatch):
    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(
            stdout="",
            stderr="does not contain a 'flake.nix'",
            returncode=1,
        )

    monkeypatch.setattr(utils, "exec_cmd", fake_exec_cmd)

    resolved = utils.try_resolve_flakeref("/nix/store/not-a-flake-output")

    assert resolved is None


def test_flakeref_realisation_error_accepts_none_stderr():
    error = utils.FlakeRefRealisationError("/tmp/my flake#pkg", None)

    assert error.stderr == ""
    assert str(error) == "Failed force-realising flakeref '/tmp/my flake#pkg'"


def test_find_deriver_uses_argv_list(monkeypatch):
    calls = []
    drv_path = "/nix/store/my drv.drv"

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout=json.dumps({drv_path: {}}))

    monkeypatch.setattr(sbomnix_nix, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(sbomnix_nix.os.path, "exists", lambda path: path == drv_path)

    resolved = sbomnix_nix.find_deriver("/nix/store/my output")

    assert resolved == drv_path
    assert calls == [
        (
            [
                "nix",
                "derivation",
                "show",
                "/nix/store/my output",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
            ],
            {"raise_on_error": False, "log_error": False},
        )
    ]


def test_get_flake_metadata_uses_argv_list(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout='{"path": "/nix/store/nixpkgs"}', returncode=0)

    monkeypatch.setattr(scanner, "exec_cmd", fake_exec_cmd)

    meta = scanner._get_flake_metadata("/tmp/my flake")

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


def test_run_nix_visualize_uses_argv_list(tmp_path, monkeypatch):
    calls = []
    output_path = tmp_path / "graph output.csv"

    class FakeTempFile:
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


def test_get_flake_metadata_strips_nixpkgs_prefix_without_splitting_spaces(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout='{"path": "/nix/store/nixpkgs"}', returncode=0)

    monkeypatch.setattr(scanner, "exec_cmd", fake_exec_cmd)

    scanner._get_flake_metadata("nixpkgs=/tmp/my flake")

    assert calls[0][0][3] == "/tmp/my flake"


def test_meta_reads_nix_path_entry_with_spaces(monkeypatch):
    scanned = []

    monkeypatch.setenv("NIX_PATH", "foo=/tmp/other:nixpkgs=/tmp/my flake")
    monkeypatch.setattr(Meta, "_scan", lambda self, path: scanned.append(path) or path)

    resolved = Meta().get_nixpkgs_meta()

    assert resolved == "/tmp/my flake"
    assert scanned == ["/tmp/my flake"]


@pytest.mark.parametrize(
    ("buildtime", "expected_cmd"),
    [
        (False, ["vulnix", "/nix/store/my target", "-C", "--json"]),
        (True, ["vulnix", "/nix/store/my target", "--json"]),
    ],
)
def test_scan_vulnix_uses_argv_lists(monkeypatch, buildtime, expected_cmd):
    calls = []
    parsed = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout="[]", stderr="", returncode=0)

    monkeypatch.setattr("vulnxscan.vulnscan.exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        VulnScan, "_parse_vulnix", lambda self, stdout: parsed.append(stdout)
    )

    scanner_obj = VulnScan()
    scanner_obj.scan_vulnix("/nix/store/my target", buildtime=buildtime)

    assert parsed == ["[]"]
    assert calls == [
        (
            expected_cmd,
            {"raise_on_error": False, "return_error": True, "log_error": False},
        )
    ]
