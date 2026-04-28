#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared pytest fixtures for the test suite."""

import os
import re
import subprocess
import time
from pathlib import Path

import pytest

REPOROOT = Path(__file__).resolve().parent.parent
INTEGRATION_DIR = REPOROOT / "tests" / "integration"
RESOURCES_DIR = REPOROOT / "tests" / "resources"


def _output_mentions_repology_host(output):
    patterns = (
        r"https://repology\.org(?:/|$)",
        r"host=['\"]repology\.org['\"]",
        r"HTTPSConnectionPool\(host=['\"]repology\.org['\"]",
    )
    return any(re.search(pattern, output) for pattern in patterns)


def _pythonpath_with_repo_root(env):
    repo_root = REPOROOT.as_posix()
    pythonpath = env.get("PYTHONPATH", "")
    if not pythonpath:
        env["PYTHONPATH"] = repo_root
        return env
    paths = pythonpath.split(os.pathsep)
    if repo_root not in paths:
        env["PYTHONPATH"] = f"{pythonpath}{os.pathsep}{repo_root}"
    return env


@pytest.fixture(name="test_work_dir")
def fixture_test_work_dir(tmp_path):
    """Return a per-test working directory."""
    return Path(tmp_path)


@pytest.fixture(name="test_nix_drv", scope="session")
def fixture_test_nix_drv():
    """Instantiate a small test derivation chain once per test session."""
    test_derivation = RESOURCES_DIR / "test-derivation-chain.nix"
    ret = subprocess.run(
        ["nix-instantiate", test_derivation.as_posix()],
        capture_output=True,
        encoding="utf-8",
        check=True,
    )
    drv = Path(ret.stdout.strip())
    assert drv.exists()
    return drv


@pytest.fixture(name="test_nix_result", scope="session")
def fixture_test_nix_result(test_nix_drv, tmp_path_factory):
    """Build nixpkgs.hello once per test session."""
    build_dir = tmp_path_factory.mktemp("nix-build")
    result = build_dir / "result"
    cmd = ["nix-build", test_nix_drv.as_posix(), "-o", result.as_posix()]
    subprocess.run(cmd, check=True)
    assert result.exists()
    return result


@pytest.fixture(name="test_cdx_sbom", scope="session")
def fixture_test_cdx_sbom():
    """Return a static CycloneDX SBOM fixture for offline SBOM-input tests."""
    sbom = RESOURCES_DIR / "sample_cdx_sbom.json"
    assert sbom.exists()
    return sbom


@pytest.fixture(name="_run_python_script")
def fixture_run_python_script(test_work_dir):
    """Invoke a Python entrypoint from an isolated test workdir."""

    def _run(args, **kwargs):
        env = _pythonpath_with_repo_root(os.environ.copy())
        kwargs.setdefault("cwd", test_work_dir)
        check = kwargs.pop("check", True)
        return subprocess.run(args, check=check, env=env, **kwargs)

    return _run


@pytest.fixture(name="_run_python_script_retry_on_repology_network_error")
def fixture_run_python_script_retry_on_repology_network_error(_run_python_script):
    """Retry transient repology.org connectivity failures before failing."""

    def _run(args):
        markers = [
            "requests.exceptions.ConnectTimeout",
            "requests.exceptions.ConnectionError",
            "requests.exceptions.ReadTimeout",
            "urllib3.exceptions.ConnectTimeoutError",
            "urllib3.exceptions.ReadTimeoutError",
            "Max retries exceeded",
            "Connection timed out",
            "Temporary failure in name resolution",
            "Name or service not known",
        ]
        retry_delays = [15, 45]
        last_ret = None
        for attempt in range(len(retry_delays) + 1):
            ret = _run_python_script(args, check=False, capture_output=True, text=True)
            if ret.returncode == 0:
                return ret
            last_ret = ret
            output = "\n".join(filter(None, [ret.stdout, ret.stderr]))
            is_repology_network_error = _output_mentions_repology_host(output) and any(
                marker in output for marker in markers
            )
            if not is_repology_network_error or attempt >= len(retry_delays):
                ret.check_returncode()
            delay = retry_delays[attempt]
            print(
                f"repology.org request failed with a transient network error; "
                f"retrying in {delay}s (attempt {attempt + 2}/{len(retry_delays) + 1})"
            )
            time.sleep(delay)
        last_ret.check_returncode()
        return last_ret

    return _run


def pytest_collection_modifyitems(items):
    """Mark integration tests based on their path."""
    for item in items:
        path = Path(str(item.fspath)).resolve()
        if INTEGRATION_DIR in path.parents:
            item.add_marker(pytest.mark.integration)
