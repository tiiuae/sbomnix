#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-function-docstring

"""Focused tests for nixpkgs metadata source selection."""

import json
import pathlib
from types import SimpleNamespace

import pytest

from common.errors import SbomnixError
from sbomnix import meta as sbomnix_meta
from sbomnix import meta_source as sbomnix_meta_source


def test_classify_meta_nixpkgs_reserved_modes_before_explicit_source():
    assert (
        sbomnix_meta.classify_meta_nixpkgs(sbomnix_meta.META_NIXPKGS_NIX_PATH)
        == sbomnix_meta.META_NIXPKGS_NIX_PATH
    )
    assert sbomnix_meta.classify_meta_nixpkgs("/nix/store/source") == "explicit"


def test_get_nixpkgs_meta_with_source_records_flakeref_lock(monkeypatch, tmp_path):
    nixpkgs_path = tmp_path / "nixpkgs"
    (nixpkgs_path / "lib").mkdir(parents=True)
    (nixpkgs_path / "lib" / ".version").write_text("25.11\n", encoding="utf-8")
    scanned = []

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nixref_to_nixpkgs_path",
        lambda _nixref: nixpkgs_path,
    )
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan",
        lambda self, path: scanned.append(path) or "df",
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".#target",
        original_ref=".#target",
    )

    assert df_meta == "df"
    assert scanned == [nixpkgs_path.as_posix()]
    assert source == sbomnix_meta.NixpkgsMetaSource(
        method="flakeref-lock",
        path=nixpkgs_path.as_posix(),
        flakeref=".#target",
        version="25.11",
    )


def test_get_nixpkgs_meta_with_source_records_opt_in_nix_path(monkeypatch):
    scanned = []

    monkeypatch.setenv("NIX_PATH", "foo=/tmp/other:nixpkgs=/tmp/my flake")
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan",
        lambda self, path: scanned.append(path) or "df",
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=None,
        original_ref="/nix/store/target",
        explicit_nixpkgs=sbomnix_meta.META_NIXPKGS_NIX_PATH,
    )

    assert df_meta == "df"
    assert scanned == ["/tmp/my flake"]
    assert source == sbomnix_meta.NixpkgsMetaSource(
        method="nix-path",
        path="/tmp/my flake",
        message="NIX_PATH metadata source may not match the target",
    )


def test_explicit_nix_path_source_requires_nixpkgs_entry(monkeypatch):
    def fail_if_scanned(self, path):
        raise AssertionError(f"nix-path scan should not run: {path}")

    monkeypatch.setenv("NIX_PATH", "foo=/tmp/other")
    monkeypatch.setattr(sbomnix_meta.Meta, "_scan", fail_if_scanned)

    with pytest.raises(SbomnixError, match="NIX_PATH.*nixpkgs="):
        sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
            target_path="/nix/store/target",
            flakeref=None,
            original_ref="/nix/store/target",
            explicit_nixpkgs=sbomnix_meta.META_NIXPKGS_NIX_PATH,
        )


def test_path_target_without_source_skips_nix_path_metadata(monkeypatch):
    def fail_if_scanned(self, path):
        raise AssertionError(f"path-target scan should be skipped: {path}")

    monkeypatch.setenv("NIX_PATH", "nixpkgs=/tmp/nixpkgs")
    monkeypatch.setattr(sbomnix_meta.Meta, "_scan", fail_if_scanned)

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/resolved-target",
        flakeref=None,
        original_ref="./result",
    )

    assert df_meta is None
    assert source.method == "none"
    assert source.path is None
    assert "store-path target" in source.message
    assert "./result" not in source.message
    assert "--meta-nixpkgs" in source.message


def test_explicit_store_path_source_records_explicit_method(monkeypatch, tmp_path):
    nixpkgs_path = tmp_path / "nixpkgs"
    (nixpkgs_path / "lib").mkdir(parents=True)
    (nixpkgs_path / "lib" / ".version").write_text("25.11\n", encoding="utf-8")
    scanned = []

    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan",
        lambda self, path: scanned.append(path) or "df",
    )
    monkeypatch.setattr(
        sbomnix_meta_source,
        "is_nix_store_path",
        lambda path: path.as_posix() == nixpkgs_path.as_posix(),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        explicit_nixpkgs=nixpkgs_path.as_posix(),
    )

    assert df_meta == "df"
    assert scanned == [nixpkgs_path.as_posix()]
    assert source == sbomnix_meta.NixpkgsMetaSource(
        method="explicit",
        path=nixpkgs_path.as_posix(),
        version="25.11",
    )


def test_explicit_flakeref_source_resolves_nixpkgs_path(monkeypatch):
    nixpkgs_path = "/nix/store/abc-source"
    scanned = []

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nixref_to_nixpkgs_path",
        lambda _nixref: pathlib.Path(nixpkgs_path),
    )
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan",
        lambda self, path: scanned.append(path) or "df",
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        explicit_nixpkgs="github:NixOS/nixpkgs?rev=abc",
    )

    assert df_meta == "df"
    assert scanned == [nixpkgs_path]
    assert source == sbomnix_meta.NixpkgsMetaSource(
        method="explicit",
        path=nixpkgs_path,
        flakeref="github:NixOS/nixpkgs?rev=abc",
    )


def test_mutable_explicit_path_is_normalized_before_scanning(monkeypatch, tmp_path):
    mutable_path = tmp_path / "nixpkgs-checkout"
    mutable_path.mkdir()
    store_path = pathlib.Path("/nix/store/normalized-source")
    scanned = []

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nixref_to_nixpkgs_path",
        lambda nixref: store_path if nixref == mutable_path.as_posix() else None,
    )
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan",
        lambda self, path: scanned.append(path) or "df",
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        explicit_nixpkgs=mutable_path.as_posix(),
    )

    assert df_meta == "df"
    assert scanned == [store_path.as_posix()]
    assert source == sbomnix_meta.NixpkgsMetaSource(
        method="explicit",
        path=store_path.as_posix(),
        flakeref=mutable_path.as_posix(),
    )


def test_mutable_explicit_path_is_rejected_if_not_cache_safe(monkeypatch, tmp_path):
    mutable_path = tmp_path / "nixpkgs-checkout"
    mutable_path.mkdir()

    monkeypatch.setattr(
        sbomnix_meta_source, "nixref_to_nixpkgs_path", lambda _nixref: None
    )

    with pytest.raises(SbomnixError, match="immutable /nix/store source"):
        sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
            target_path="/nix/store/target",
            explicit_nixpkgs=mutable_path.as_posix(),
        )


def test_nixos_toplevel_flakeref_prefers_configuration_pkgs_path(
    monkeypatch,
    tmp_path,
):
    nixpkgs_path = tmp_path / "nixpkgs"
    nixpkgs_path.mkdir()
    calls = []
    expressions = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        calls.append(cmd)
        if cmd == [
            "nix",
            "eval",
            "--raw",
            '/flake#nixosConfigurations."host".pkgs.path',
        ]:
            return SimpleNamespace(stdout=f"{nixpkgs_path}\n", returncode=0)
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta_source,
        "nixref_to_nixpkgs_path",
        lambda _nixref: (_ for _ in ()).throw(
            AssertionError("lock-node fallback should not run")
        ),
    )
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_expression",
        lambda self, expression, *, cache_key=None, impure=False: (
            expressions.append((expression, cache_key, impure)) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref="/flake#nixosConfigurations.host.config.system.build.toplevel",
        original_ref="/flake#nixosConfigurations.host.config.system.build.toplevel",
    )

    assert df_meta is fake_df
    assert calls == [
        ["nix", "eval", "--raw", '/flake#nixosConfigurations."host".pkgs.path']
    ]
    assert source.method == "flakeref-target"
    assert source.path == nixpkgs_path.as_posix()
    assert source.flakeref == '/flake#nixosConfigurations."host".pkgs.path'
    assert source.message == "Scanning evaluated NixOS package set from flakeref"
    assert expressions == [
        (
            'let\n  flake = builtins.getFlake "/flake";\nin\n'
            '  flake.nixosConfigurations."host".pkgs\n',
            None,
            False,
        )
    ]


def test_nixos_toplevel_expression_locks_relative_flake_refs(
    monkeypatch,
    tmp_path,
):
    nixpkgs_path = tmp_path / "nixpkgs"
    nixpkgs_path.mkdir()
    source_path = "/nix/store/root-source"
    calls = []
    expressions = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        calls.append(cmd)
        if cmd == [
            "nix",
            "eval",
            "--raw",
            '.#nixosConfigurations."host".pkgs.path',
        ]:
            return SimpleNamespace(stdout=f"{nixpkgs_path}\n", returncode=0)
        if cmd == ["nix", "flake", "metadata", ".", "--json"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc"},
                    }
                ),
                returncode=0,
            )
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_expression",
        lambda self, expression, *, cache_key=None, impure=False: (
            expressions.append((expression, cache_key, impure)) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".#nixosConfigurations.host.config.system.build.toplevel",
        original_ref=".#nixosConfigurations.host.config.system.build.toplevel",
    )

    locked_ref = f"path:{source_path}?narHash=sha256-abc"
    assert df_meta is fake_df
    assert source.method == "flakeref-target"
    assert source.flakeref == '.#nixosConfigurations."host".pkgs.path'
    assert calls == [
        ["nix", "eval", "--raw", '.#nixosConfigurations."host".pkgs.path'],
        ["nix", "flake", "metadata", ".", "--json"],
    ]
    cache_key = "nixos-pkgs:" + json.dumps(
        [locked_ref, "host"],
        separators=(",", ":"),
    )
    assert expressions == [
        (
            f'let\n  flake = builtins.getFlake "{locked_ref}";\nin\n'
            '  flake.nixosConfigurations."host".pkgs\n',
            cache_key,
            False,
        )
    ]


def test_nixos_toplevel_expression_preserves_locked_subflake_dir(
    monkeypatch,
    tmp_path,
):
    nixpkgs_path = tmp_path / "nixpkgs"
    nixpkgs_path.mkdir()
    source_path = "/nix/store/root-source"
    calls = []
    expressions = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        calls.append(cmd)
        if cmd == [
            "nix",
            "eval",
            "--raw",
            'path:.?dir=sub/flake#nixosConfigurations."host".pkgs.path',
        ]:
            return SimpleNamespace(stdout=f"{nixpkgs_path}\n", returncode=0)
        if cmd == ["nix", "flake", "metadata", "path:.?dir=sub/flake", "--json"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {
                            "narHash": "sha256-abc",
                            "dir": "sub/flake",
                        },
                    }
                ),
                returncode=0,
            )
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_expression",
        lambda self, expression, *, cache_key=None, impure=False: (
            expressions.append((expression, cache_key, impure)) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=(
            "path:.?dir=sub/flake#nixosConfigurations.host.config.system.build.toplevel"
        ),
        original_ref=(
            "path:.?dir=sub/flake#nixosConfigurations.host.config.system.build.toplevel"
        ),
    )

    locked_ref = f"path:{source_path}?narHash=sha256-abc&dir=sub/flake"
    assert df_meta is fake_df
    assert source.method == "flakeref-target"
    assert calls == [
        [
            "nix",
            "eval",
            "--raw",
            'path:.?dir=sub/flake#nixosConfigurations."host".pkgs.path',
        ],
        ["nix", "flake", "metadata", "path:.?dir=sub/flake", "--json"],
    ]
    cache_key = "nixos-pkgs:" + json.dumps(
        [locked_ref, "host"],
        separators=(",", ":"),
    )
    assert expressions == [
        (
            f'let\n  flake = builtins.getFlake "{locked_ref}";\nin\n'
            '  flake.nixosConfigurations."host".pkgs\n',
            cache_key,
            False,
        )
    ]


def test_nixos_toplevel_flakeref_handles_quoted_configuration_names(
    monkeypatch,
    tmp_path,
):
    nixpkgs_path = tmp_path / "nixpkgs"
    nixpkgs_path.mkdir()
    expressions = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd == [
            "nix",
            "eval",
            "--raw",
            '/flake#nixosConfigurations."host.example.com".pkgs.path',
        ]:
            return SimpleNamespace(stdout=f"{nixpkgs_path}\n", returncode=0)
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_expression",
        lambda self, expression, *, cache_key=None, impure=False: (
            expressions.append((expression, cache_key, impure)) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=(
            '/flake#nixosConfigurations."host.example.com".config.system.build.toplevel'
        ),
        original_ref=(
            '/flake#nixosConfigurations."host.example.com".config.system.build.toplevel'
        ),
    )

    assert df_meta is fake_df
    assert source.method == "flakeref-target"
    assert source.flakeref == (
        '/flake#nixosConfigurations."host.example.com".pkgs.path'
    )
    assert expressions == [
        (
            'let\n  flake = builtins.getFlake "/flake";\nin\n'
            '  flake.nixosConfigurations."host.example.com".pkgs\n',
            None,
            False,
        )
    ]


def test_nixos_toplevel_flakeref_metadata_eval_honors_impure(monkeypatch, tmp_path):
    nixpkgs_path = tmp_path / "nixpkgs"
    nixpkgs_path.mkdir()
    calls = []
    expressions = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        calls.append(cmd)
        return SimpleNamespace(stdout=f"{nixpkgs_path}\n", returncode=0)

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_expression",
        lambda self, expression, *, cache_key=None, impure=False: (
            expressions.append((expression, cache_key, impure)) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref="/flake#nixosConfigurations.host.config.system.build.toplevel",
        original_ref="/flake#nixosConfigurations.host.config.system.build.toplevel",
        impure=True,
    )

    assert df_meta is fake_df
    assert source.method == "flakeref-target"
    assert calls == [
        [
            "nix",
            "eval",
            "--raw",
            '/flake#nixosConfigurations."host".pkgs.path',
            "--impure",
        ]
    ]
    assert expressions == [
        (
            'let\n  flake = builtins.getFlake "/flake";\nin\n'
            '  flake.nixosConfigurations."host".pkgs\n',
            None,
            True,
        )
    ]
    assert source.expression_cache_key is None
    assert source.expression_impure is True


def test_nixos_toplevel_expression_cache_uses_only_stable_refs(monkeypatch, tmp_path):
    nixpkgs_path = tmp_path / "nixpkgs"
    nixpkgs_path.mkdir()
    expressions = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout=f"{nixpkgs_path}\n", returncode=0)

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_expression",
        lambda self, expression, *, cache_key=None, impure=False: (
            expressions.append((expression, cache_key, impure)) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=(
            "github:example/flake?rev=abc"
            '#nixosConfigurations."host:8080".config.system.build.toplevel'
        ),
        original_ref=(
            "github:example/flake?rev=abc"
            '#nixosConfigurations."host:8080".config.system.build.toplevel'
        ),
    )

    cache_key = "nixos-pkgs:" + json.dumps(
        ["github:example/flake?rev=abc", "host:8080"],
        separators=(",", ":"),
    )
    assert df_meta is fake_df
    assert source.method == "flakeref-target"
    assert expressions == [
        (
            'let\n  flake = builtins.getFlake "github:example/flake?rev=abc";\n'
            "in\n"
            '  flake.nixosConfigurations."host:8080".pkgs\n',
            cache_key,
            False,
        )
    ]


def test_nixos_toplevel_expression_scan_fallback_updates_source(
    monkeypatch,
    tmp_path,
):
    nixpkgs_path = tmp_path / "nixpkgs"
    nixpkgs_path.mkdir()
    fake_df = SimpleNamespace(empty=False)
    scanned = []

    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout=f"{nixpkgs_path}\n", returncode=0)

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_expression",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan",
        lambda self, path: scanned.append(path) or fake_df,
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref="/flake#nixosConfigurations.host.config.system.build.toplevel",
        original_ref="/flake#nixosConfigurations.host.config.system.build.toplevel",
    )

    assert df_meta is fake_df
    assert scanned == [nixpkgs_path.as_posix()]
    assert source.method == "flakeref-target"
    assert source.expression is None
    assert source.expression_cache_key is None
    assert source.expression_impure is False
    assert "fell back to base nixpkgs source metadata" in source.message
    assert "evaluated NixOS package set" not in source.message


def test_nixos_toplevel_flakeref_falls_back_to_revision(monkeypatch, tmp_path):
    nixpkgs_path = tmp_path / "nixpkgs"
    nixpkgs_path.mkdir()
    calls = []
    scanned = []

    def fake_exec_cmd(cmd, **_kwargs):
        calls.append(cmd)
        if cmd == [
            "nix",
            "eval",
            "--raw",
            '/flake#nixosConfigurations."host".pkgs.path',
        ]:
            return SimpleNamespace(stdout="", stderr="missing", returncode=1)
        if cmd == [
            "nix",
            "eval",
            "--raw",
            '/flake#nixosConfigurations."host".config.system.nixos.revision',
        ]:
            return SimpleNamespace(stdout="abc123\n", returncode=0)
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta_source,
        "nixref_to_nixpkgs_path",
        lambda nixref: (
            nixpkgs_path if nixref == "github:NixOS/nixpkgs?rev=abc123" else None
        ),
    )
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan",
        lambda self, path: scanned.append(path) or "df",
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref="/flake#nixosConfigurations.host.config.system.build.toplevel",
        original_ref="/flake#nixosConfigurations.host.config.system.build.toplevel",
    )

    assert df_meta == "df"
    assert calls == [
        ["nix", "eval", "--raw", '/flake#nixosConfigurations."host".pkgs.path'],
        [
            "nix",
            "eval",
            "--raw",
            '/flake#nixosConfigurations."host".config.system.nixos.revision',
        ],
    ]
    assert scanned == [nixpkgs_path.as_posix()]
    assert source == sbomnix_meta.NixpkgsMetaSource(
        method="flakeref-target",
        path=nixpkgs_path.as_posix(),
        flakeref="github:NixOS/nixpkgs?rev=abc123",
        rev="abc123",
        message=(
            "Resolved nixpkgs from NixOS configuration revision as a "
            "best-effort fallback; this may not represent forked, patched, "
            "dirty, local, or offline nixpkgs inputs"
        ),
    )


def test_nixos_toplevel_flakeref_without_pkgs_or_revision_returns_message(
    monkeypatch,
):
    calls = []

    def fake_exec_cmd(cmd, **_kwargs):
        calls.append(cmd)
        return SimpleNamespace(stdout="", stderr="missing", returncode=1)

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta_source,
        "nixref_to_nixpkgs_path",
        lambda _nixref: None,
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref="/flake#nixosConfigurations.host.config.system.build.toplevel",
        original_ref="/flake#nixosConfigurations.host.config.system.build.toplevel",
    )

    assert df_meta is None
    assert calls == [
        ["nix", "eval", "--raw", '/flake#nixosConfigurations."host".pkgs.path'],
        [
            "nix",
            "eval",
            "--raw",
            '/flake#nixosConfigurations."host".config.system.nixos.revision',
        ],
    ]
    assert source.method == "none"
    assert source.path is None
    assert "NixOS configuration flakeref" in source.message
    assert "--meta-nixpkgs" in source.message


def test_plain_nixos_configuration_attrset_is_not_target_inferred(
    monkeypatch,
    tmp_path,
):
    nixpkgs_path = tmp_path / "lock-source"
    nixpkgs_path.mkdir()
    scanned = []

    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan",
        lambda self, path: scanned.append(path) or "df",
    )
    monkeypatch.setattr(
        sbomnix_meta_source,
        "nixref_to_nixpkgs_path",
        lambda _nixref: nixpkgs_path,
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref="/flake#nixosConfigurations.host",
        original_ref="/flake#nixosConfigurations.host",
    )

    assert df_meta == "df"
    assert scanned == [nixpkgs_path.as_posix()]
    assert source.method == "flakeref-lock"


def test_meta_scan_uses_already_resolved_scanner_path(monkeypatch):
    calls = []
    fake_df = SimpleNamespace(empty=False)

    class FakeScanner:
        """Scanner stand-in that records normalized scan paths."""

        def scan(self, path):
            raise AssertionError(f"scan should not resolve path again: {path}")

        def scan_path(self, path):
            calls.append(path)

        def to_df(self):
            return fake_df

    meta = sbomnix_meta.Meta()
    monkeypatch.setattr(meta.cache, "get", lambda _key: None)
    monkeypatch.setattr(meta.cache, "set", lambda **_kwargs: None)
    monkeypatch.setattr(sbomnix_meta, "NixMetaScanner", FakeScanner)

    assert meta._scan("/nix/store/source") is fake_df  # pylint: disable=protected-access
    assert calls == ["/nix/store/source"]
