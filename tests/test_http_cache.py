#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for shared cache-path configuration."""

from pathlib import Path

from common.http import create_cached_limited_session
from sbomnix import cache_paths as sbomnix_cache_paths
from sbomnix.cache_paths import cache_root, http_cache_name, meta_lock_path


def test_cache_root_prefers_xdg_cache_home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", tmp_path.as_posix())

    assert cache_root() == tmp_path / "sbomnix"


def test_cache_root_falls_back_to_home_cache(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    assert cache_root() == tmp_path / ".cache" / "sbomnix"


def test_cached_http_session_uses_shared_sbomnix_cache_path():
    session = create_cached_limited_session()
    try:
        assert Path(session.cache.db_path) == http_cache_name().with_suffix(".sqlite")
    finally:
        session.close()


def test_meta_lock_uses_shared_sbomnix_cache_root(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", tmp_path.as_posix())

    assert meta_lock_path() == tmp_path / "sbomnix" / "meta.lock"


def test_cache_root_falls_back_to_tmp_when_xdg_and_home_are_unwritable(
    monkeypatch, tmp_path
):
    xdg_root = tmp_path / "xdg"
    home_root = tmp_path / "home"
    tmp_root = tmp_path / "tmp"
    orig_mkdir = Path.mkdir

    monkeypatch.setenv("XDG_CACHE_HOME", xdg_root.as_posix())
    monkeypatch.setattr(Path, "home", lambda: home_root)
    monkeypatch.setattr(
        sbomnix_cache_paths.tempfile,
        "gettempdir",
        tmp_root.as_posix,
    )
    monkeypatch.setattr(sbomnix_cache_paths, "getuser", lambda: "tester")

    def fake_mkdir(self, *args, **kwargs):
        if self in {
            xdg_root / "sbomnix",
            home_root / ".cache" / "sbomnix",
        }:
            raise PermissionError("unwritable")
        return orig_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fake_mkdir)

    assert cache_root() == tmp_root / "tester_sbomnix_cache"


def test_cache_root_falls_back_to_tmp_when_existing_dirs_are_not_writable(
    monkeypatch, tmp_path
):
    xdg_root = tmp_path / "xdg"
    home_root = tmp_path / "home"
    tmp_root = tmp_path / "tmp"
    xdg_cache = xdg_root / "sbomnix"
    home_cache = home_root / ".cache" / "sbomnix"
    xdg_cache.mkdir(parents=True)
    home_cache.mkdir(parents=True)
    real_access = sbomnix_cache_paths.os.access

    monkeypatch.setenv("XDG_CACHE_HOME", xdg_root.as_posix())
    monkeypatch.setattr(Path, "home", lambda: home_root)
    monkeypatch.setattr(
        sbomnix_cache_paths.tempfile,
        "gettempdir",
        tmp_root.as_posix,
    )
    monkeypatch.setattr(sbomnix_cache_paths, "getuser", lambda: "tester")

    def fake_access(path, mode):
        path = Path(path)
        if path in {xdg_cache, home_cache}:
            return False
        return real_access(path, mode)

    monkeypatch.setattr(sbomnix_cache_paths.os, "access", fake_access)

    assert cache_root() == tmp_root / "tester_sbomnix_cache"
