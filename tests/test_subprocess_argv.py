#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

"""Unit tests for whitespace-safe subprocess argv construction."""

import json
from types import SimpleNamespace

import pytest

from common import flakeref as common_flakeref
from common.errors import FlakeRefRealisationError, FlakeRefResolutionError
from common.nix_utils import get_nix_store_dir, parse_nix_derivation_show
from common.proc import exec_cmd
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

    monkeypatch.setattr(common_flakeref, "exec_cmd", fake_exec_cmd)

    resolved = common_flakeref.try_resolve_flakeref(
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

    monkeypatch.setattr(common_flakeref, "exec_cmd", fake_exec_cmd)

    with pytest.raises(FlakeRefRealisationError, match="build failed"):
        common_flakeref.try_resolve_flakeref("/tmp/my flake#pkg", force_realise=True)


def test_try_resolve_flakeref_raises_on_failed_eval_for_flakeref(monkeypatch):
    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout="", stderr="attribute missing", returncode=1)

    monkeypatch.setattr(common_flakeref, "exec_cmd", fake_exec_cmd)

    with pytest.raises(FlakeRefResolutionError, match="attribute missing"):
        common_flakeref.try_resolve_flakeref(".#missing")


def test_try_resolve_flakeref_returns_none_for_non_flake_path(monkeypatch):
    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(
            stdout="",
            stderr="does not contain a 'flake.nix'",
            returncode=1,
        )

    monkeypatch.setattr(common_flakeref, "exec_cmd", fake_exec_cmd)

    resolved = common_flakeref.try_resolve_flakeref("/nix/store/not-a-flake-output")

    assert resolved is None


@pytest.mark.parametrize("path", ["missing", "./missing", "foo/bar"])
def test_try_resolve_flakeref_returns_none_for_missing_relative_paths(
    monkeypatch, path
):
    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout="", stderr="dummy eval failure", returncode=1)

    monkeypatch.setattr(common_flakeref, "exec_cmd", fake_exec_cmd)

    resolved = common_flakeref.try_resolve_flakeref(path)

    assert resolved is None


def test_try_resolve_flakeref_returns_none_for_existing_fragment_path_when_eval_fails(
    tmp_path, monkeypatch
):
    existing_path = tmp_path / "contains#hash"
    existing_path.mkdir()
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(
            stdout="",
            stderr="does not contain a 'flake.nix'",
            returncode=1,
        )

    monkeypatch.setattr(common_flakeref, "exec_cmd", fake_exec_cmd)

    resolved = common_flakeref.try_resolve_flakeref(existing_path.as_posix())

    assert resolved is None
    assert calls


def test_flakeref_realisation_error_accepts_none_stderr():
    error = FlakeRefRealisationError(".#pkg", stderr=None)

    assert error.stderr == ""
    assert str(error) == "Failed force-realising flakeref '.#pkg'"


def test_flake_ref_resolution_error_preserves_stderr_verbatim():
    error = FlakeRefResolutionError(".#pkg", stderr="stderr details\n")

    assert error.stderr == "stderr details\n"
    assert str(error) == "Failed evaluating flakeref '.#pkg': stderr details"


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
        return SimpleNamespace(
            stdout='[{"pname": "hello", "version": "1.0", "affected_by": []}]',
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr("vulnxscan.vulnscan.exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        VulnScan,
        "_parse_vulnix",
        lambda self, stdout: parsed.append(stdout),
    )

    VulnScan().scan_vulnix("/nix/store/my target", buildtime=buildtime)

    assert calls == [
        (
            expected_cmd,
            {"raise_on_error": False, "return_error": True, "log_error": False},
        )
    ]
    assert parsed == ['[{"pname": "hello", "version": "1.0", "affected_by": []}]']
