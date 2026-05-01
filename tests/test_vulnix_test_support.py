#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the vulnix test wrapper helpers."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from tests import vulnix_test_support


def test_build_vulnix_test_env_prepends_wrapper_dir(tmp_path):
    """Wrapper dir should take precedence on PATH for test subprocesses."""
    wrapper_dir = tmp_path / "bin"
    config = vulnix_test_support.VulnixTestConfig(
        wrapper_dir=wrapper_dir,
        effective_mode="dummy",
        effective_cache_dir=None,
        real_vulnix=None,
    )
    env = vulnix_test_support.build_vulnix_test_env(
        {"PATH": "/usr/bin"},
        config=config,
    )
    assert env["PATH"] == os.pathsep.join([str(wrapper_dir), "/usr/bin"])
    assert env["SBOMNIX_TEST_VULNIX_EFFECTIVE_MODE"] == "dummy"
    assert env["SBOMNIX_TEST_REAL_VULNIX"] == ""
    assert "SBOMNIX_TEST_VULNIX_EFFECTIVE_CACHE_DIR" not in env


def test_dummy_vulnix_wrapper_returns_empty_json(tmp_path):
    """Dummy mode should behave like a no-op vulnix process."""
    config = vulnix_test_support.configure_vulnix_for_tests(
        tmp_root=tmp_path,
        effective_mode="dummy",
        cache_dir=tmp_path / "cache",
        real_vulnix=None,
    )
    env = vulnix_test_support.build_vulnix_test_env({}, config=config)
    ret = subprocess.run(
        [str(config.wrapper_dir / "vulnix"), "--json"],
        check=True,
        capture_output=True,
        encoding="utf-8",
        env=env,
    )
    assert ret.stdout == "[]"
    assert ret.stderr == ""


def test_real_vulnix_wrapper_forwards_cache_dir_and_args(tmp_path):
    """Real mode wrapper should exec the underlying binary with the cache dir."""
    real_vulnix = tmp_path / "real-vulnix"
    real_vulnix.write_text(
        """#!/bin/sh
set -eu
printf '%s\\n' "$@"
""",
        encoding="utf-8",
    )
    real_vulnix.chmod(0o755)
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "Data.fs").write_text("ready", encoding="utf-8")
    config = vulnix_test_support.configure_vulnix_for_tests(
        tmp_root=tmp_path,
        effective_mode="real",
        cache_dir=cache_dir,
        real_vulnix=real_vulnix.as_posix(),
    )
    env = vulnix_test_support.build_vulnix_test_env({}, config=config)
    env = {"PATH": os.environ.get("PATH", os.defpath), **env}
    ret = subprocess.run(
        [str(config.wrapper_dir / "vulnix"), "target", "-C", "--json"],
        check=True,
        capture_output=True,
        encoding="utf-8",
        env=env,
    )
    assert ret.stdout.splitlines() == [
        "--cache-dir",
        cache_dir.as_posix(),
        "target",
        "-C",
        "--json",
    ]


def test_configure_vulnix_for_tests_rejects_unknown_mode(tmp_path):
    """configure_vulnix_for_tests should only accept dummy or real modes."""
    with pytest.raises(ValueError, match="invalid effective vulnix mode"):
        vulnix_test_support.configure_vulnix_for_tests(
            tmp_root=tmp_path,
            effective_mode="surprise",
            cache_dir=tmp_path / "cache",
            real_vulnix=None,
        )


def test_real_vulnix_wrapper_shows_clear_error_when_binary_missing(tmp_path):
    """Real mode wrapper should fail with a readable message if env is stale."""
    config = vulnix_test_support.configure_vulnix_for_tests(
        tmp_root=tmp_path,
        effective_mode="dummy",
        cache_dir=tmp_path / "cache",
        real_vulnix=None,
    )
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "SBOMNIX_TEST_VULNIX_EFFECTIVE_MODE": "real",
    }
    ret = subprocess.run(
        [str(config.wrapper_dir / "vulnix"), "--json"],
        check=False,
        capture_output=True,
        encoding="utf-8",
        env=env,
    )
    assert ret.returncode != 0
    assert "SBOMNIX_TEST_REAL_VULNIX is empty" in ret.stderr


def test_ensure_real_vulnix_cache_surfaces_warmup_errors(tmp_path):
    """Warm-up failures should include stderr details in the raised error."""
    real_vulnix = tmp_path / "fake-vulnix"
    real_vulnix.write_text(
        """#!/bin/sh
set -eu
echo 'vulnix boom' >&2
exit 7
""",
        encoding="utf-8",
    )
    real_vulnix.chmod(0o755)
    result = tmp_path / "build" / "result"
    result.parent.mkdir(parents=True, exist_ok=True)
    result.write_text("placeholder", encoding="utf-8")

    with pytest.raises(
        RuntimeError, match="vulnix cache warm-up scan failed: vulnix boom"
    ):
        vulnix_test_support.ensure_real_vulnix_cache(
            tmp_path / "cache",
            build_root=tmp_path / "build",
            real_vulnix=real_vulnix.as_posix(),
            test_derivation=tmp_path / "derivation.nix",
        )


@pytest.mark.real_vulnix
def test_real_vulnix_wrapper_executes_real_binary(tmp_path):
    """Opt-in smoke test that executes the real vulnix binary via the wrapper."""
    real_vulnix = shutil.which("vulnix")
    if real_vulnix is None:
        pytest.skip("'vulnix' is not available in PATH")
    cache_dir = tmp_path / "real-cache"
    config = vulnix_test_support.configure_vulnix_for_tests(
        tmp_root=tmp_path,
        effective_mode="real",
        cache_dir=cache_dir,
        real_vulnix=real_vulnix,
    )
    env = vulnix_test_support.build_vulnix_test_env({}, config=config)
    env = {"PATH": os.environ.get("PATH", os.defpath), **env}
    ret = subprocess.run(
        [str(config.wrapper_dir / "vulnix"), "--version"],
        check=True,
        capture_output=True,
        encoding="utf-8",
        env=env,
    )
    assert "vulnix" in ret.stdout.lower() or "vulnix" in ret.stderr.lower()
