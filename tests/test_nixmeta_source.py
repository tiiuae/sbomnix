#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for nixpkgs metadata source selection."""

import json
from types import SimpleNamespace

import pandas as pd
import pytest

from sbomnix import meta as sbomnix_meta
from sbomnix import meta_source as sbomnix_meta_source

_NAMES = ["hello-2.12.3", "glibc-2.42"]


def test_flake_meta_source_for_plain_flakeref(monkeypatch):
    """Plain flakeref → flake-meta, pkgs_expression derived from the locked flake."""
    source_path = "/nix/store/abc-flake-src"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        # NixOS config probe and other nix eval --raw calls all fail: ".#target"
        # has no nixosConfigurations.target, so we fall through to lock-graph path.
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        # Both the initial lock call (on ".") and the lock-graph check (on the
        # stable path ref) return the same minimal metadata with no locks field,
        # so lock-graph resolution returns None and the import-flake fallback fires.
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {"path": source_path, "locked": {"narHash": "sha256-xyz"}}
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append((names, pkgs_expr)) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".#target",
        original_ref=".#target",
        store_names=_NAMES,
    )

    locked_ref = f"path:{source_path}?narHash=sha256-xyz"
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == locked_ref
    assert source.path == source_path
    assert len(scanned) == 1
    assert scanned[0][1] == f"import (builtins.getFlake {json.dumps(locked_ref)}) {{}}"


def test_flake_meta_source_for_plain_flakeref_preserves_locked_subflake_dir(
    monkeypatch,
):
    """Direct-import fallback must export the locked subflake path and version."""
    source_path = "/nix/store/abc-flake-src"
    locked_dir = "sub/flake"
    version_reads = []
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {
                            "narHash": "sha256-xyz",
                            "dir": locked_dir,
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
        sbomnix_meta_source,
        "read_nixpkgs_version",
        lambda path: version_reads.append(path) or "24.11pre",
    )
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append((names, pkgs_expr)) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".#target",
        original_ref=".#target",
        store_names=_NAMES,
    )

    expected_path = f"{source_path}/{locked_dir}"
    locked_ref = f"path:{source_path}?narHash=sha256-xyz&dir={locked_dir}"
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == locked_ref
    assert source.path == expected_path
    assert source.version == "24.11pre"
    assert version_reads == [expected_path]
    assert len(scanned) == 1
    assert scanned[0][1] == f"import (builtins.getFlake {json.dumps(locked_ref)}) {{}}"


def test_path_target_without_flakeref_skips_metadata(monkeypatch):
    """Store-path target with no flakeref → no metadata, no scan."""

    def fail_if_scanned(*args, **kwargs):
        raise AssertionError("scan should not run for path target without flakeref")

    monkeypatch.setattr(sbomnix_meta.Meta, "_scan_store_names", fail_if_scanned)

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/resolved-target",
        flakeref=None,
        original_ref="./result",
        store_names=_NAMES,
    )

    assert df_meta is None
    assert source.method == "none"
    assert source.path is None
    assert "store-path" in source.message
    assert "--meta-nixpkgs" not in source.message


def test_nixos_toplevel_flakeref_returns_flake_meta_source(monkeypatch):
    """NixOS toplevel flakeref → flake-meta source; cache key uses locked path."""
    source_path = "/nix/store/root-source"
    calls = []
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(
                returncode=0, stdout="/nix/store/abc-nixpkgs-src", stderr=""
            )
        calls.append(cmd)
        # _flake_meta_cache_key calls _locked_flake_ref_from_metadata for the
        # cache key even when the flake path is not lockable for scanning.
        if cmd == ["nix", "flake", "metadata", "/flake", "--json"]:
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append((names, cache_key, impure)) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref="/flake#nixosConfigurations.host.config.system.build.toplevel",
        original_ref="/flake#nixosConfigurations.host.config.system.build.toplevel",
        store_names=_NAMES,
    )

    # For an absolute path that doesn't exist, _flake_ref_for_expression returns
    # the path unchanged (no locking). The cache key is separately computed via
    # _flake_meta_cache_key which does call _locked_flake_ref_from_metadata.
    base_cache_key = (
        f"flake-meta:path:{source_path}?narHash=sha256-abc"
        "#nixosConfigurations.host.config.system.build.toplevel"
    )
    # _with_buildtime_suffix appends :rt for runtime (buildtime=False default)
    cache_key = base_cache_key + ":rt"
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == '/flake#nixosConfigurations."host".pkgs.path'
    assert source.path == "/nix/store/abc-nixpkgs-src"
    assert source.expression_cache_key == cache_key
    assert source.expression_impure is False
    assert scanned == [(_NAMES, cache_key, False)]


def test_nixos_toplevel_flakeref_locks_relative_flake_refs(monkeypatch):
    """Relative .# NixOS toplevel → flake locked via metadata."""
    source_path = "/nix/store/root-source"
    calls = []
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(
                returncode=0, stdout="/nix/store/abc-nixpkgs-src", stderr=""
            )
        calls.append(cmd)
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append((names, cache_key, impure)) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".#nixosConfigurations.host.config.system.build.toplevel",
        original_ref=".#nixosConfigurations.host.config.system.build.toplevel",
        store_names=_NAMES,
    )

    locked_ref = (
        f"path:{source_path}?narHash=sha256-abc"
        "#nixosConfigurations.host.config.system.build.toplevel"
    )
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == (
        f'path:{source_path}?narHash=sha256-abc#nixosConfigurations."host".pkgs.path'
    )
    assert source.path == "/nix/store/abc-nixpkgs-src"
    assert source.expression_cache_key == f"flake-meta:{locked_ref}:rt"
    assert calls == [["nix", "flake", "metadata", ".", "--json"]]


def test_nixos_toplevel_flakeref_preserves_locked_subflake_dir(monkeypatch):
    """dir= query param is preserved in the locked ref."""
    source_path = "/nix/store/root-source"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(
                returncode=0, stdout="/nix/store/abc-nixpkgs-src", stderr=""
            )
        if cmd == ["nix", "flake", "metadata", "path:.?dir=sub/flake", "--json"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc", "dir": "sub/flake"},
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(names) or fake_df
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
        store_names=_NAMES,
    )

    locked_ref = (
        f"path:{source_path}?narHash=sha256-abc&dir=sub/flake"
        "#nixosConfigurations.host.config.system.build.toplevel"
    )
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == (
        f"path:{source_path}?narHash=sha256-abc&dir=sub/flake"
        '#nixosConfigurations."host".pkgs.path'
    )
    assert source.path == "/nix/store/abc-nixpkgs-src"
    assert source.expression_cache_key == f"flake-meta:{locked_ref}:rt"


def test_nixos_toplevel_flakeref_honors_impure(monkeypatch):
    """impure=True is forwarded to the exec_cmd lock call and to _scan_store_names."""
    calls = []
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(
                returncode=0, stdout="/nix/store/abc-nixpkgs-src", stderr=""
            )
        calls.append(cmd)
        return SimpleNamespace(
            stdout=json.dumps(
                {"path": "/nix/store/src", "locked": {"narHash": "sha256-abc"}}
            ),
            returncode=0,
        )

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append((names, impure)) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref="/flake#nixosConfigurations.host.config.system.build.toplevel",
        original_ref="/flake#nixosConfigurations.host.config.system.build.toplevel",
        impure=True,
        store_names=_NAMES,
    )

    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.expression_impure is True
    assert calls == [["nix", "flake", "metadata", "/flake", "--json", "--impure"]]
    assert scanned[0][1] is True


def test_nixos_toplevel_flakeref_cache_uses_stable_rev_refs(monkeypatch):
    """flakeref with ?rev= produces a stable cache key."""
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(
            stdout=json.dumps(
                {"path": "/nix/store/src", "locked": {"narHash": "sha256-abc"}}
            ),
            returncode=0,
        )

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append((names, cache_key, impure)) or fake_df
        ),
    )

    flake_with_rev = "github:example/flake?rev=abc"
    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=(
            f"{flake_with_rev}"
            '#nixosConfigurations."host:8080".config.system.build.toplevel'
        ),
        original_ref=(
            f"{flake_with_rev}"
            '#nixosConfigurations."host:8080".config.system.build.toplevel'
        ),
        store_names=_NAMES,
    )

    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.expression_cache_key is not None
    assert flake_with_rev in source.expression_cache_key
    assert "host:8080" in source.expression_cache_key


def test_flake_meta_scan_failure_returns_message(monkeypatch):
    """flake-meta scan failure replaces source message."""
    monkeypatch.setattr(
        sbomnix_meta.Meta, "_scan_store_names", lambda *_args, **_kwargs: None
    )

    source = sbomnix_meta.NixpkgsMetaSource(
        method="flake-meta",
        flakeref="nixpkgs#hello",
        pkgs_expression="import /nix/store/abc-nixpkgs {}",
    )
    df_meta, out_source = sbomnix_meta.Meta()._scan_source_with_source(
        source, store_names=["hello-2.12.3"]
    )

    assert df_meta is None
    assert out_source.method == "flake-meta"
    assert "meta.nix scan failed" in out_source.message


def test_flake_meta_partial_scan_records_warning(monkeypatch):
    """Partial meta.nix batch failures must be surfaced in the returned source."""

    class FakeScanner:
        had_failures = True

        def scan_store_names(self, names, *, impure=False, pkgs_expr=None):
            self._names = list(names)

        def to_df(self):
            return pd.DataFrame(
                {"name": self._names, "meta_license_short": ["MIT"] * len(self._names)}
            )

    meta = sbomnix_meta.Meta()
    monkeypatch.setattr(meta.cache, "get", lambda _key: None)
    monkeypatch.setattr(meta.cache, "set", lambda **_kwargs: None)
    monkeypatch.setattr(sbomnix_meta, "NixMetaScanner", FakeScanner)

    source = sbomnix_meta.NixpkgsMetaSource(
        method="flake-meta",
        flakeref="nixpkgs#hello",
        pkgs_expression="pkgs",
        expression_cache_key="flake-meta:path:/nix/store/abc?narHash=sha256-x#hello",
    )
    df_meta, out_source = meta._scan_source_with_source(
        source, store_names=["hello-2.12.3"]
    )

    assert df_meta is not None and not df_meta.empty
    assert out_source.method == "flake-meta"
    assert "partially failed" in out_source.message


def test_flake_meta_empty_scan_reports_no_matches(monkeypatch):
    """An empty successful scan should not be reported as a scan failure."""
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_store_names",
        lambda *_args, **_kwargs: pd.DataFrame(),
    )

    source = sbomnix_meta.NixpkgsMetaSource(
        method="flake-meta",
        flakeref="nixpkgs#hello",
        pkgs_expression="import /nix/store/abc-nixpkgs {}",
    )
    df_meta, out_source = sbomnix_meta.Meta()._scan_source_with_source(
        source, store_names=["ghaf.iso"]
    )

    assert df_meta is None
    assert out_source.method == "flake-meta"
    assert "No packages matched" in out_source.message


def test_plain_nixos_configuration_attrset_uses_flake_meta(monkeypatch):
    """/flake#nixosConfigurations.host (no toplevel suffix) → flake-meta, no metadata."""
    scanned = []

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(
        sbomnix_meta_source,
        "exec_cmd",
        lambda cmd, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(names) or None
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref="/flake#nixosConfigurations.host",
        original_ref="/flake#nixosConfigurations.host",
        store_names=_NAMES,
    )

    # Non-toplevel flakerefs have no pkgs_expression, so the scan is skipped.
    assert df_meta is None
    assert source.method == "flake-meta"
    assert source.flakeref == "/flake#nixosConfigurations.host"
    assert len(scanned) == 0
    assert "nixpkgs" in source.message.lower()


def test_nixos_config_shorthand_flakeref_uses_config_pkgs(monkeypatch):
    """ghaf#hostname → NixOS config probe succeeds → pkgs from nixosConfigurations."""
    source_path = "/nix/store/abc-ghaf-src"
    scanned = []
    fake_df = SimpleNamespace(empty=False)
    locked_ref = f"path:{source_path}?narHash=sha256-ghaf"
    pkgs_path_ref = (
        f'{locked_ref}#nixosConfigurations."lenovo-x1-carbon-gen11-debug".pkgs.path'
    )

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"] and cmd[3] == pkgs_path_ref:
            return SimpleNamespace(
                returncode=0, stdout="/nix/store/abc-nixpkgs-src", stderr=""
            )
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:4] == ["flake", "metadata", "/home/user/ghaf"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {"path": source_path, "locked": {"narHash": "sha256-ghaf"}}
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append((names, pkgs_expr)) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref="/home/user/ghaf#lenovo-x1-carbon-gen11-debug",
        original_ref="/home/user/ghaf#lenovo-x1-carbon-gen11-debug",
        store_names=_NAMES,
    )

    expected_pkgs = (
        f"(builtins.getFlake {json.dumps(locked_ref)})"
        '.nixosConfigurations."lenovo-x1-carbon-gen11-debug".pkgs'
    )
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == pkgs_path_ref
    assert source.path == "/nix/store/abc-nixpkgs-src"
    assert source.pkgs_expression == expected_pkgs
    assert len(scanned) == 1
    assert scanned[0][1] == expected_pkgs


def test_flake_meta_no_pkgs_expression_returns_message():
    """flake-meta source without pkgs_expression → informative message, no scan."""
    source = sbomnix_meta.NixpkgsMetaSource(
        method="flake-meta",
        flakeref="nixpkgs#hello",
        pkgs_expression=None,
    )
    df_meta, out_source = sbomnix_meta.Meta()._scan_source_with_source(
        source, store_names=["hello-2.12.3"]
    )

    assert df_meta is None
    assert out_source.method == "flake-meta"
    assert "nixpkgs" in out_source.message.lower()


def test_meta_scan_store_names_calls_scanner_directly(monkeypatch):
    """_scan_store_names calls scanner.scan_store_names without re-resolving."""
    calls = []
    fake_df = SimpleNamespace(empty=False)

    class FakeScanner:
        had_failures = False

        def scan_store_names(self, names, *, impure=False, pkgs_expr=None):
            calls.append((names, impure))

        def to_df(self):
            return fake_df

    meta = sbomnix_meta.Meta()
    monkeypatch.setattr(meta.cache, "get", lambda _key: None)
    monkeypatch.setattr(meta.cache, "set", lambda **_kwargs: None)
    monkeypatch.setattr(sbomnix_meta, "NixMetaScanner", FakeScanner)

    cache_key = "flake-meta:path:/nix/store/abc?narHash=sha256-x#hello"
    result = meta._scan_store_names(["hello-2.12.3"], cache_key=cache_key)

    assert result is fake_df
    assert calls == [(["hello-2.12.3"], False)]


def test_flake_meta_cache_key_stable_narHash_returns_key():
    key = sbomnix_meta_source.NixpkgsMetaSourceResolver._flake_meta_cache_key(
        "path:/nix/store/abc123?narHash=sha256-xyz#hello"
    )
    assert key == "flake-meta:path:/nix/store/abc123?narHash=sha256-xyz#hello"


def test_flake_meta_cache_key_stable_rev_returns_key():
    key = sbomnix_meta_source.NixpkgsMetaSourceResolver._flake_meta_cache_key(
        "github:NixOS/nixpkgs?rev=abc123#hello"
    )
    assert key == "flake-meta:github:NixOS/nixpkgs?rev=abc123#hello"


def test_flake_meta_cache_key_unstable_ref_returns_none(monkeypatch):
    monkeypatch.setattr(
        sbomnix_meta_source.NixpkgsMetaSourceResolver,
        "_nix_flake_metadata",
        lambda *_args, **_kwargs: None,
    )
    key = sbomnix_meta_source.NixpkgsMetaSourceResolver._flake_meta_cache_key(
        "github:NixOS/nixpkgs/nixos-unstable#hello"
    )
    assert key is None


@pytest.mark.parametrize(
    "flakeref",
    [
        "github:NixOS/nixpkgs?rev=abc#hello",
        "path:/nix/store/abc123?narHash=sha256-xyz#hello",
    ],
)
def test_flake_meta_cache_key_no_nix_call_for_stable_refs(flakeref, monkeypatch):
    """Stable refs (rev= or narHash=) don't trigger nix flake metadata calls."""
    monkeypatch.setattr(
        sbomnix_meta_source.NixpkgsMetaSourceResolver,
        "_nix_flake_metadata",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("_nix_flake_metadata should not be called for stable refs")
        ),
    )
    key = sbomnix_meta_source.NixpkgsMetaSourceResolver._flake_meta_cache_key(flakeref)
    assert key is not None


def test_buildtime_suffix_bt(monkeypatch):
    """buildtime=True appends :bt to the cache key instead of :rt."""
    source_path = "/nix/store/abc-src"
    fake_df = SimpleNamespace(empty=False)

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(
            stdout=json.dumps(
                {"path": source_path, "locked": {"narHash": "sha256-abc"}}
            ),
            returncode=0,
        )

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_meta.Meta,
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: fake_df,
    )

    _, source_bt = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        flakeref=".#hello",
        store_names=_NAMES,
        buildtime=True,
    )
    _, source_rt = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        flakeref=".#hello",
        store_names=_NAMES,
        buildtime=False,
    )

    assert source_bt.expression_cache_key.endswith(":bt")
    assert source_rt.expression_cache_key.endswith(":rt")


def test_scan_store_names_cache_key_includes_names(monkeypatch):
    """Each distinct name set must get its own cache entry.

    Regression test: the old key f"expr:{cache_key}" did not include the name
    set, so a shallow first run could cache partial metadata and a deeper second
    run with the same expression key would silently reuse the incomplete result.
    """
    scan_calls = []

    class FakeScanner:
        had_failures = False

        def scan_store_names(self, names, *, impure=False, pkgs_expr=None):
            scan_calls.append(list(names))
            self._names = list(names)

        def to_df(self):
            return pd.DataFrame(
                {"name": self._names, "meta_license_short": ["MIT"] * len(self._names)}
            )

    cache_store = {}

    def fake_get(key):
        return cache_store.get(key)

    def fake_set(**kwargs):
        cache_store[kwargs["key"]] = kwargs["value"]

    meta = sbomnix_meta.Meta()
    monkeypatch.setattr(meta.cache, "get", fake_get)
    monkeypatch.setattr(meta.cache, "set", fake_set)
    monkeypatch.setattr(sbomnix_meta, "NixMetaScanner", FakeScanner)

    cache_key = "flake-meta:path:/nix/store/abc?narHash=sha256-x#hello"
    names_shallow = ["hello-2.12.3", "glibc-2.42"]
    names_deep = ["hello-2.12.3", "glibc-2.42", "gcc-12.3.0", "bash-5.2.0"]

    meta._scan_store_names(names_shallow, cache_key=cache_key, pkgs_expr="pkgs")
    assert len(scan_calls) == 1

    meta._scan_store_names(names_deep, cache_key=cache_key, pkgs_expr="pkgs")
    assert len(scan_calls) == 2, (
        "A deeper name set must not reuse the cache entry for a shallower set"
    )
    assert scan_calls[1] == names_deep


def test_scan_store_names_cache_key_includes_meta_nix_hash(monkeypatch):
    """Changing meta.nix logic must invalidate old metadata cache entries."""
    scan_calls = []

    class FakeScanner:
        had_failures = False

        def scan_store_names(self, names, *, impure=False, pkgs_expr=None):
            scan_calls.append(list(names))
            self._names = list(names)

        def to_df(self):
            return pd.DataFrame(
                {"name": self._names, "meta_license_short": ["MIT"] * len(self._names)}
            )

    cache_store = {}

    def fake_get(key):
        return cache_store.get(key)

    def fake_set(**kwargs):
        cache_store[kwargs["key"]] = kwargs["value"]

    meta = sbomnix_meta.Meta()
    monkeypatch.setattr(meta.cache, "get", fake_get)
    monkeypatch.setattr(meta.cache, "set", fake_set)
    monkeypatch.setattr(sbomnix_meta, "NixMetaScanner", FakeScanner)
    monkeypatch.setattr(sbomnix_meta, "_meta_nix_hash", lambda: "hash-a")

    cache_key = "flake-meta:path:/nix/store/abc?narHash=sha256-x#hello"
    names = ["hello-2.12.3", "glibc-2.42"]

    meta._scan_store_names(names, cache_key=cache_key, pkgs_expr="pkgs")
    assert len(scan_calls) == 1

    monkeypatch.setattr(sbomnix_meta, "_meta_nix_hash", lambda: "hash-b")
    meta._scan_store_names(names, cache_key=cache_key, pkgs_expr="pkgs")
    assert len(scan_calls) == 2, (
        "A changed meta.nix hash must invalidate the previous cache entry"
    )


def test_partial_batch_failure_skips_cache(monkeypatch):
    """A partial scan (some batches failed) must not be written to the cache.

    Regression test: previously any non-empty dataframe was cached regardless
    of whether all batches succeeded, so a transient meta.nix failure could
    permanently poison the cache entry until TTL expiry.
    """
    call_count = [0]

    class FakeScanner:
        had_failures = True  # simulate one batch having failed

        def scan_store_names(self, names, *, impure=False, pkgs_expr=None):
            call_count[0] += 1
            self._names = list(names)

        def to_df(self):
            return pd.DataFrame(
                {"name": self._names, "meta_license_short": ["MIT"] * len(self._names)}
            )

    cache_written = []

    def fake_set(**kwargs):
        cache_written.append(kwargs["key"])

    meta = sbomnix_meta.Meta()
    monkeypatch.setattr(meta.cache, "get", lambda _key: None)
    monkeypatch.setattr(meta.cache, "set", fake_set)
    monkeypatch.setattr(sbomnix_meta, "NixMetaScanner", FakeScanner)

    cache_key = "flake-meta:path:/nix/store/abc?narHash=sha256-x#hello"
    meta._scan_store_names(["hello-2.12.3"], cache_key=cache_key, pkgs_expr="pkgs")

    assert not cache_written, (
        "Partial scan result (had_failures=True) must not be written to cache"
    )
    # The partial result is still returned for the current run.
    assert call_count[0] == 1

    # A second call must re-scan (not hit a cached partial result).
    meta._scan_store_names(["hello-2.12.3"], cache_key=cache_key, pkgs_expr="pkgs")
    assert call_count[0] == 2, (
        "Second call must re-scan when previous result was not cached"
    )


def test_flake_lock_source_honors_impure(monkeypatch):
    """impure=True is forwarded through resolve_flakeref_lock_source to the returned source."""
    source_path = "/nix/store/abc-flake-src"
    commands_seen = []

    def fake_exec_cmd(cmd, **_kwargs):
        commands_seen.append(cmd)
        if "metadata" in cmd:
            return SimpleNamespace(
                stdout=json.dumps(
                    {"path": source_path, "locked": {"narHash": "sha256-xyz"}}
                ),
                returncode=0,
            )
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)

    resolver = sbomnix_meta_source.NixpkgsMetaSourceResolver()
    source = resolver.resolve_flakeref_lock_source(".#target", impure=True)

    assert source.expression_impure is True
    metadata_cmds = [c for c in commands_seen if "metadata" in c]
    assert metadata_cmds and "--impure" in metadata_cmds[0], (
        "--impure was not forwarded to the nix flake metadata call"
    )


def test_dotted_attr_flakeref_skips_nixos_probe(monkeypatch):
    """Dotted attr (e.g. haskellPackages.vector) skips the NixOS config probe."""
    source_path = "/nix/store/abc-nixpkgs-src"
    eval_raw_calls = []

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            eval_raw_calls.append(cmd)
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(
            stdout=json.dumps(
                {"path": source_path, "locked": {"narHash": "sha256-abc"}}
            ),
            returncode=0,
        )

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)

    source = (
        sbomnix_meta_source.NixpkgsMetaSourceResolver().resolve_flakeref_lock_source(
            ".#haskellPackages.vector"
        )
    )

    assert eval_raw_calls == [], "NixOS config probe must not fire for dotted attr"
    assert source.pkgs_expression is not None
    assert "nixosConfigurations" not in source.pkgs_expression
    locked_ref = f"path:{source_path}?narHash=sha256-abc"
    assert (
        source.pkgs_expression
        == f"import (builtins.getFlake {json.dumps(locked_ref)}) {{}}"
    )


def test_nixpkgs_package_attr_skips_nixos_probe(monkeypatch):
    """Simple nixpkgs package attrs must not trigger the NixOS config probe."""
    source_path = "/nix/store/abc-nixpkgs-src"
    eval_raw_calls = []

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            eval_raw_calls.append(cmd)
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "description": "A collection of packages for the Nix package manager",
                    "path": source_path,
                    "locked": {
                        "owner": "NixOS",
                        "repo": "nixpkgs",
                        "narHash": "sha256-abc",
                    },
                }
            ),
            returncode=0,
        )

    monkeypatch.setattr(
        sbomnix_meta_source,
        "nix_cmd",
        lambda *args, impure=False: ["nix", *args] + (["--impure"] if impure else []),
    )
    monkeypatch.setattr(sbomnix_meta_source, "exec_cmd", fake_exec_cmd)

    source = (
        sbomnix_meta_source.NixpkgsMetaSourceResolver().resolve_flakeref_lock_source(
            "github:NixOS/nixpkgs/nixos-unstable#git"
        )
    )

    assert eval_raw_calls == [], "NixOS config probe must not fire for nixpkgs attrs"
    assert source.pkgs_expression is not None
    assert "nixosConfigurations" not in source.pkgs_expression
    locked_ref = f"path:{source_path}?narHash=sha256-abc"
    assert source.flakeref == locked_ref
    assert (
        source.pkgs_expression
        == f"import (builtins.getFlake {json.dumps(locked_ref)}) {{}}"
    )


def test_resolve_flakeref_lock_source_caches_flake_metadata_and_result(monkeypatch):
    """Repeated resolution reuses the cached metadata and final source object."""
    metadata_calls = []
    eval_raw_calls = []

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            eval_raw_calls.append(cmd)
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            metadata_calls.append(cmd)
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": "/nix/store/abc-flake-src",
                        "locked": {"narHash": "sha256-xyz"},
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

    resolver = sbomnix_meta_source.NixpkgsMetaSourceResolver()
    first = resolver.resolve_flakeref_lock_source(".#target")
    second = resolver.resolve_flakeref_lock_source(".#target")

    assert first is second
    assert len(metadata_calls) == 1
    assert len(eval_raw_calls) == 1


def test_third_party_flake_lock_graph_resolution(monkeypatch):
    """Third-party flake with root.inputs.nixpkgs → pkgs from the pinned nixpkgs."""
    source_path = "/nix/store/abc-ghaf-src"
    nixpkgs_rev = "abc123def456"
    nixpkgs_nar = "sha256-nixpkgshash"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    lock_graph = {
        "root": "root",
        "version": 7,
        "nodes": {
            "root": {"inputs": {"nixpkgs": "nixpkgs"}},
            "nixpkgs": {
                "locked": {
                    "type": "github",
                    "owner": "NixOS",
                    "repo": "nixpkgs",
                    "rev": nixpkgs_rev,
                    "narHash": nixpkgs_nar,
                }
            },
        },
    }

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-ghaf"},
                        "locks": lock_graph,
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(pkgs_expr) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".",
        original_ref=".",
        store_names=_NAMES,
    )

    from urllib.parse import urlencode

    expected_pkgs = (
        f"import (builtins.getFlake "
        f"{json.dumps('github:NixOS/nixpkgs?' + urlencode({'rev': nixpkgs_rev, 'narHash': nixpkgs_nar}, safe='/'))}"
        f") {{}}"
    )
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert (
        source.flakeref
        == f"github:NixOS/nixpkgs?rev={nixpkgs_rev}&narHash={nixpkgs_nar}"
    )
    assert source.rev == nixpkgs_rev
    assert source.path is None
    assert len(scanned) == 1
    assert scanned[0] == expected_pkgs


def test_third_party_flake_lock_graph_preserves_locked_subflake_dir(monkeypatch):
    """dir= on a locked nixpkgs flake input must be preserved in the source ref."""
    source_path = "/nix/store/abc-ghaf-src"
    nixpkgs_rev = "abc123def456"
    nixpkgs_nar = "sha256-nixpkgshash"
    nixpkgs_dir = "pkgs/nixpkgs"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    lock_graph = {
        "root": "root",
        "version": 7,
        "nodes": {
            "root": {"inputs": {"nixpkgs": "nixpkgs"}},
            "nixpkgs": {
                "locked": {
                    "type": "github",
                    "owner": "NixOS",
                    "repo": "nixpkgs",
                    "rev": nixpkgs_rev,
                    "narHash": nixpkgs_nar,
                    "dir": nixpkgs_dir,
                }
            },
        },
    }

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-ghaf"},
                        "locks": lock_graph,
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(pkgs_expr) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".",
        original_ref=".",
        store_names=_NAMES,
    )

    from urllib.parse import urlencode

    nixpkgs_ref = "github:NixOS/nixpkgs?" + urlencode(
        {"rev": nixpkgs_rev, "narHash": nixpkgs_nar, "dir": nixpkgs_dir},
        safe="/",
    )
    expected_pkgs = f"import (builtins.getFlake {json.dumps(nixpkgs_ref)}) {{}}"
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == nixpkgs_ref
    assert source.rev == nixpkgs_rev
    assert len(scanned) == 1
    assert scanned[0] == expected_pkgs


def test_third_party_flake_override_chain_input(monkeypatch):
    """root.inputs.nixpkgs = ["nixpkgs_3"] override-chain form resolves via last element."""
    source_path = "/nix/store/abc-src"
    nixpkgs_rev = "overriderev"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    lock_graph = {
        "root": "root",
        "version": 7,
        "nodes": {
            "root": {"inputs": {"nixpkgs": ["nixpkgs", "nixpkgs_3"]}},
            "nixpkgs": {
                "locked": {
                    "type": "github",
                    "owner": "NixOS",
                    "repo": "nixpkgs",
                    "rev": "wrong-rev",
                }
            },
            "nixpkgs_3": {
                "locked": {
                    "type": "github",
                    "owner": "NixOS",
                    "repo": "nixpkgs",
                    "rev": nixpkgs_rev,
                }
            },
        },
    }

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc"},
                        "locks": lock_graph,
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(pkgs_expr) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".",
        original_ref=".",
        store_names=_NAMES,
    )

    from urllib.parse import urlencode

    expected_pkgs = (
        f"import (builtins.getFlake "
        f"{json.dumps('github:NixOS/nixpkgs?' + urlencode({'rev': nixpkgs_rev}, safe='/'))}"
        f") {{}}"
    )
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == f"github:NixOS/nixpkgs?rev={nixpkgs_rev}"
    assert source.rev == nixpkgs_rev
    assert len(scanned) == 1
    assert scanned[0] == expected_pkgs, (
        "override-chain input must resolve via last list element (nixpkgs_3), not nixpkgs"
    )


def test_third_party_flake_git_locked_nixpkgs(monkeypatch):
    """root.inputs.nixpkgs locked via git type produces a git+ pkgs expression."""
    source_path = "/nix/store/abc-src"
    git_url = "https://git.example.com/nixpkgs"
    git_ref = "refs/heads/main"
    git_rev = "deadbeef"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    lock_graph = {
        "root": "root",
        "version": 7,
        "nodes": {
            "root": {"inputs": {"nixpkgs": "nixpkgs"}},
            "nixpkgs": {
                "locked": {
                    "type": "git",
                    "url": git_url,
                    "ref": git_ref,
                    "rev": git_rev,
                }
            },
        },
    }

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc"},
                        "locks": lock_graph,
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(pkgs_expr) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".",
        original_ref=".",
        store_names=_NAMES,
    )

    from urllib.parse import urlencode

    expected_pkgs = (
        f"import (builtins.getFlake "
        f"{json.dumps('git+' + git_url + '?' + urlencode({'ref': git_ref, 'rev': git_rev}, safe='/'))}"
        f") {{}}"
    )
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert (
        source.flakeref
        == f"git+{git_url}?{urlencode({'ref': git_ref, 'rev': git_rev}, safe='/')}"
    )
    assert source.rev == git_rev
    assert len(scanned) == 1
    assert scanned[0] == expected_pkgs


def test_third_party_flake_git_locked_nixpkgs_without_ref(monkeypatch):
    """Git-locked nixpkgs with only url+rev must still resolve via git+ flakeref."""
    source_path = "/nix/store/abc-src"
    git_url = "https://git.example.com/nixpkgs"
    git_rev = "deadbeef"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    lock_graph = {
        "root": "root",
        "version": 7,
        "nodes": {
            "root": {"inputs": {"nixpkgs": "nixpkgs"}},
            "nixpkgs": {
                "locked": {
                    "type": "git",
                    "url": git_url,
                    "rev": git_rev,
                }
            },
        },
    }

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc"},
                        "locks": lock_graph,
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(pkgs_expr) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".",
        original_ref=".",
        store_names=_NAMES,
    )

    expected_ref = f"git+{git_url}?rev={git_rev}"
    expected_pkgs = f"import (builtins.getFlake {json.dumps(expected_ref)}) {{}}"
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == expected_ref
    assert source.rev == git_rev
    assert len(scanned) == 1
    assert scanned[0] == expected_pkgs


def test_third_party_flake_tarball_locked_nixpkgs_preserves_narhash_and_dir(
    monkeypatch,
):
    """Tarball-locked nixpkgs inputs must keep narHash and dir in the source ref."""
    source_path = "/nix/store/abc-src"
    tarball_url = "https://releases.nixos.org/nixpkgs/nixexprs.tar.xz"
    tarball_nar = "sha256-tarballhash"
    tarball_dir = "pkgs/by-name"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    lock_graph = {
        "root": "root",
        "version": 7,
        "nodes": {
            "root": {"inputs": {"nixpkgs": "nixpkgs"}},
            "nixpkgs": {
                "locked": {
                    "type": "tarball",
                    "url": tarball_url,
                    "narHash": tarball_nar,
                    "dir": tarball_dir,
                }
            },
        },
    }

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc"},
                        "locks": lock_graph,
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(pkgs_expr) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".",
        original_ref=".",
        store_names=_NAMES,
    )

    from urllib.parse import urlencode

    tarball_ref = (
        tarball_url
        + "?"
        + urlencode(
            {"narHash": tarball_nar, "dir": tarball_dir},
            safe="/",
        )
    )
    expected_pkgs = f"import (builtins.getFlake {json.dumps(tarball_ref)}) {{}}"
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == tarball_ref
    assert len(scanned) == 1
    assert scanned[0] == expected_pkgs


def test_third_party_flake_unambiguous_git_nixpkgs_without_root_input(monkeypatch):
    """A lone git nixpkgs node is accepted even without root.inputs.nixpkgs."""
    source_path = "/nix/store/abc-src"
    git_url = "https://github.com/NixOS/nixpkgs"
    git_ref = "refs/heads/nixos-unstable"
    git_rev = "deadbeef"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    lock_graph = {
        "root": "root",
        "version": 7,
        "nodes": {
            "root": {"inputs": {}},
            "stable": {
                "locked": {
                    "type": "git",
                    "url": git_url,
                    "ref": git_ref,
                    "rev": git_rev,
                }
            },
        },
    }

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc"},
                        "locks": lock_graph,
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(pkgs_expr) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".",
        original_ref=".",
        store_names=_NAMES,
    )

    from urllib.parse import urlencode

    git_ref_locked = (
        "git+"
        + git_url
        + "?"
        + urlencode(
            {"ref": git_ref, "rev": git_rev},
            safe="/",
        )
    )
    expected_pkgs = f"import (builtins.getFlake {json.dumps(git_ref_locked)}) {{}}"
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == git_ref_locked
    assert source.rev == git_rev
    assert len(scanned) == 1
    assert scanned[0] == expected_pkgs


def test_third_party_flake_unambiguous_tarball_nixpkgs_without_root_input(
    monkeypatch,
):
    """A lone tarball nixpkgs node is accepted even without root.inputs.nixpkgs."""
    source_path = "/nix/store/abc-src"
    tarball_url = "https://releases.nixos.org/nixpkgs/nixexprs.tar.xz"
    tarball_nar = "sha256-tarballhash"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    lock_graph = {
        "root": "root",
        "version": 7,
        "nodes": {
            "root": {"inputs": {}},
            "stable": {
                "locked": {
                    "type": "tarball",
                    "url": tarball_url,
                    "narHash": tarball_nar,
                }
            },
        },
    }

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc"},
                        "locks": lock_graph,
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(pkgs_expr) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".",
        original_ref=".",
        store_names=_NAMES,
    )

    tarball_ref = f"{tarball_url}?narHash={tarball_nar}"
    expected_pkgs = f"import (builtins.getFlake {json.dumps(tarball_ref)}) {{}}"
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == tarball_ref
    assert len(scanned) == 1
    assert scanned[0] == expected_pkgs


def test_third_party_flake_path_locked_nixpkgs_preserves_subdir(monkeypatch):
    """A path-locked nixpkgs input with dir= must import and export the subdirectory."""
    source_path = "/nix/store/abc-src"
    nixpkgs_path = "/nix/store/locked-nixpkgs"
    nixpkgs_dir = "subflake/nixpkgs"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    lock_graph = {
        "root": "root",
        "version": 7,
        "nodes": {
            "root": {"inputs": {"nixpkgs": "nixpkgs"}},
            "nixpkgs": {
                "locked": {
                    "type": "path",
                    "path": nixpkgs_path,
                    "dir": nixpkgs_dir,
                }
            },
        },
    }

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc"},
                        "locks": lock_graph,
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(pkgs_expr) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".",
        original_ref=".",
        store_names=_NAMES,
    )

    expected_path = f"{nixpkgs_path}/{nixpkgs_dir}"
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == f"path:{nixpkgs_path}?dir={nixpkgs_dir}"
    assert source.path == expected_path
    assert len(scanned) == 1
    assert scanned[0] == f"import {json.dumps(expected_path)} {{}}"


def test_third_party_flake_ambiguous_nixpkgs_falls_back_to_import_flake(monkeypatch):
    """Multiple nixpkgs-like nodes with no explicit root input → import-flake fallback."""
    source_path = "/nix/store/abc-src"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    lock_graph = {
        "root": "root",
        "version": 7,
        "nodes": {
            "root": {"inputs": {}},
            "nixpkgs_stable": {
                "locked": {
                    "type": "github",
                    "owner": "NixOS",
                    "repo": "nixpkgs",
                    "rev": "rev-stable",
                }
            },
            "nixpkgs_unstable": {
                "locked": {
                    "type": "github",
                    "owner": "NixOS",
                    "repo": "nixpkgs",
                    "rev": "rev-unstable",
                }
            },
        },
    }

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc"},
                        "locks": lock_graph,
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(pkgs_expr) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".",
        original_ref=".",
        store_names=_NAMES,
    )

    locked_ref = f"path:{source_path}?narHash=sha256-abc"
    expected_fallback = f"import (builtins.getFlake {json.dumps(locked_ref)}) {{}}"
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == locked_ref
    assert source.path == source_path
    assert len(scanned) == 1
    assert scanned[0] == expected_fallback


def test_third_party_flake_named_path_node_does_not_guess_nixpkgs(monkeypatch):
    """A path node named like nixpkgs must not be guessed without root.inputs.nixpkgs."""
    source_path = "/nix/store/abc-src"
    guessed_path = "/nix/store/abc-looks-like-nixpkgs"
    scanned = []
    fake_df = SimpleNamespace(empty=False)

    lock_graph = {
        "root": "root",
        "version": 7,
        "nodes": {
            "root": {"inputs": {}},
            "nixpkgs_path": {
                "locked": {
                    "type": "path",
                    "path": guessed_path,
                }
            },
        },
    }

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1:3] == ["eval", "--raw"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if cmd[1:3] == ["flake", "metadata"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "path": source_path,
                        "locked": {"narHash": "sha256-abc"},
                        "locks": lock_graph,
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
        "_scan_store_names",
        lambda self, names, *, cache_key=None, impure=False, pkgs_expr=None: (
            scanned.append(pkgs_expr) or fake_df
        ),
    )

    df_meta, source = sbomnix_meta.Meta().get_nixpkgs_meta_with_source(
        target_path="/nix/store/target",
        flakeref=".",
        original_ref=".",
        store_names=_NAMES,
    )

    locked_ref = f"path:{source_path}?narHash=sha256-abc"
    expected_fallback = f"import (builtins.getFlake {json.dumps(locked_ref)}) {{}}"
    assert df_meta is fake_df
    assert source.method == "flake-meta"
    assert source.flakeref == locked_ref
    assert source.path == source_path
    assert len(scanned) == 1
    assert scanned[0] == expected_fallback
