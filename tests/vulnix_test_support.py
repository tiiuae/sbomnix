#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for choosing the real or dummy vulnix binary in tests."""

from __future__ import annotations

import fcntl
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

_WRAPPER_BASENAME = "vulnix"


@dataclass(frozen=True)
class VulnixTestConfig:
    """Resolved vulnix test execution configuration."""

    wrapper_dir: Path
    effective_mode: str
    effective_cache_dir: Path | None
    real_vulnix: str | None


def default_vulnix_cache_dir(env: dict[str, str] | None = None) -> Path:
    """Return the real vulnix cache dir for this environment."""
    env = os.environ if env is None else env
    cache_dir = env.get("SBOMNIX_TEST_VULNIX_CACHE_DIR")
    if cache_dir:
        return Path(cache_dir).expanduser()
    return Path("~/.cache/vulnix").expanduser()


def vulnix_cache_ready(cache_dir: Path) -> bool:
    """Return True when `cache_dir` already contains a usable vulnix DB."""
    data_file = cache_dir / "Data.fs"
    return data_file.is_file() and data_file.stat().st_size > 0


def write_vulnix_wrapper(wrapper_dir: Path) -> Path:
    """Create the test-only vulnix wrapper and return its path."""
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    wrapper_path = wrapper_dir / _WRAPPER_BASENAME
    wrapper_path.write_text(
        """#!/bin/sh
set -eu

mode="${SBOMNIX_TEST_VULNIX_EFFECTIVE_MODE:?}"
if [ "$mode" = "dummy" ]; then
  printf '[]'
  exit 0
fi

real_vulnix="${SBOMNIX_TEST_REAL_VULNIX:-}"
if [ -z "$real_vulnix" ]; then
  echo "SBOMNIX_TEST_REAL_VULNIX is empty while vulnix test mode is real" >&2
  exit 2
fi
cache_dir="${SBOMNIX_TEST_VULNIX_EFFECTIVE_CACHE_DIR:-}"
if [ -n "$cache_dir" ]; then
  exec "$real_vulnix" --cache-dir "$cache_dir" "$@"
fi
exec "$real_vulnix" "$@"
""",
        encoding="utf-8",
    )
    wrapper_path.chmod(
        wrapper_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    )
    return wrapper_path


def build_vulnix_test_env(
    env: dict[str, str],
    *,
    config: VulnixTestConfig,
) -> dict[str, str]:
    """Return environment variables needed by the vulnix test wrapper."""
    env = env.copy()
    path_entries = [str(config.wrapper_dir)]
    path_entries.append(env.get("PATH", os.defpath))
    env["PATH"] = os.pathsep.join(path_entries)
    env["SBOMNIX_TEST_VULNIX_EFFECTIVE_MODE"] = config.effective_mode
    env["SBOMNIX_TEST_REAL_VULNIX"] = config.real_vulnix or ""
    if config.effective_cache_dir is not None:
        env["SBOMNIX_TEST_VULNIX_EFFECTIVE_CACHE_DIR"] = str(config.effective_cache_dir)
    else:
        env.pop("SBOMNIX_TEST_VULNIX_EFFECTIVE_CACHE_DIR", None)
    return env


def configure_vulnix_for_tests(
    *,
    tmp_root: Path,
    effective_mode: str,
    cache_dir: Path,
    real_vulnix: str | None = None,
) -> VulnixTestConfig:
    """Resolve vulnix wrapper mode and materialize the wrapper script."""
    if effective_mode not in {"dummy", "real"}:
        raise ValueError(
            f"invalid effective vulnix mode {effective_mode!r}; expected 'dummy' or 'real'"
        )
    if effective_mode == "real" and real_vulnix is None:
        real_vulnix = shutil.which("vulnix")
    if effective_mode == "real" and real_vulnix is None:
        raise RuntimeError(
            "real vulnix requested, but 'vulnix' is not available in PATH"
        )
    wrapper_dir = tmp_root / "tool-wrappers"
    write_vulnix_wrapper(wrapper_dir)
    return VulnixTestConfig(
        wrapper_dir=wrapper_dir,
        effective_mode=effective_mode,
        effective_cache_dir=cache_dir if effective_mode == "real" else None,
        real_vulnix=real_vulnix,
    )


def ensure_real_vulnix_cache(
    cache_dir: Path,
    *,
    build_root: Path,
    real_vulnix: str,
    test_derivation: Path,
) -> Path:
    """Warm a shared vulnix cache once for opt-in/manual real-vulnix test runs.

    The default test harness uses dummy vulnix and does not call this helper.
    """

    def _run_warmup_command(cmd: list[str], *, step: str) -> None:
        try:
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            stdout = (exc.stdout or "").strip()
            details = stderr or stdout or "no output captured"
            raise RuntimeError(f"{step} failed: {details}") from exc

    cache_dir.mkdir(parents=True, exist_ok=True)
    build_root.mkdir(parents=True, exist_ok=True)
    lock_path = build_root / "vulnix-cache.lock"
    with lock_path.open("w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        if vulnix_cache_ready(cache_dir):
            return cache_dir
        result_link = build_root / "result"
        if not result_link.exists():
            _run_warmup_command(
                ["nix-build", test_derivation.as_posix(), "-o", result_link.as_posix()],
                step="nix-build for vulnix cache warm-up",
            )
        _run_warmup_command(
            [
                real_vulnix,
                "--cache-dir",
                cache_dir.as_posix(),
                result_link.as_posix(),
                "-C",
                "--json",
            ],
            step="vulnix cache warm-up scan",
        )
    return cache_dir
