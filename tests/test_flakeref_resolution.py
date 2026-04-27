#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-class-docstring,missing-function-docstring

"""Focused tests for flakeref resolution helpers."""

import string
from types import SimpleNamespace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from common.errors import FlakeRefRealisationError, FlakeRefResolutionError
from common.flakeref import try_resolve_flakeref
from common.log import LOG_VERBOSE


class CapturingLogger:
    def __init__(self):
        self.records = []

    def info(self, msg, *args):
        self.records.append(("info", msg, args))

    def log(self, level, msg, *args):
        self.records.append(("log", level, msg, args))

    def debug(self, msg, *args):
        self.records.append(("debug", msg, args))


SAFE_PATH_CHARS = string.ascii_letters + string.digits + "._-"
PATH_SEGMENTS = st.text(SAFE_PATH_CHARS, min_size=1, max_size=16).filter(
    lambda segment: segment not in {".", ".."}
)
PLAIN_MISSING_PATHS = st.lists(PATH_SEGMENTS, min_size=1, max_size=3).map(
    lambda parts: "hypothesis-missing/" + "/".join(parts)
)
FLAKE_ATTRS = st.text(SAFE_PATH_CHARS, min_size=1, max_size=24)
FLAKE_REFS = st.one_of(
    FLAKE_ATTRS.map(lambda attr: f".#{attr}"),
    FLAKE_ATTRS.map(lambda attr: f"nixpkgs?ref=nixos-unstable#{attr}"),
    st.builds(
        lambda owner, repo, attr: f"github:{owner}/{repo}#{attr}",
        PATH_SEGMENTS,
        PATH_SEGMENTS,
        FLAKE_ATTRS,
    ),
)


def test_try_resolve_flakeref_uses_argv_lists():
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        if cmd[1] == "eval":
            return SimpleNamespace(stdout="/nix/store/resolved\n", returncode=0)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    resolved = try_resolve_flakeref(
        "/tmp/my flake#pkg",
        force_realise=True,
        impure=True,
        exec_cmd_fn=fake_exec_cmd,
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


def test_try_resolve_flakeref_logs_flake_progress_at_info():
    logger = CapturingLogger()

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1] == "eval":
            return SimpleNamespace(
                stdout="/nix/store/resolved\n",
                stderr="",
                returncode=0,
            )
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    resolved = try_resolve_flakeref(
        ".#hello",
        force_realise=True,
        exec_cmd_fn=fake_exec_cmd,
        log=logger,
    )

    assert resolved == "/nix/store/resolved"
    assert (
        "info",
        "Evaluating flakeref '%s'",
        (".#hello",),
    ) in logger.records
    assert (
        "info",
        "Realising flakeref '%s'",
        (".#hello",),
    ) in logger.records


def test_try_resolve_flakeref_keeps_plain_path_probe_verbose():
    logger = CapturingLogger()

    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout="", stderr="dummy eval failure", returncode=1)

    resolved = try_resolve_flakeref(
        "/nix/store/not-a-flake-output",
        exec_cmd_fn=fake_exec_cmd,
        log=logger,
    )

    assert resolved is None
    assert (
        "log",
        LOG_VERBOSE,
        "Evaluating '%s'",
        ("/nix/store/not-a-flake-output",),
    ) in (logger.records)
    assert not [record for record in logger.records if record[0] == "info"]


def test_try_resolve_flakeref_raises_on_failed_force_realise():
    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1] == "eval":
            return SimpleNamespace(stdout="/nix/store/resolved\n", returncode=0)
        return SimpleNamespace(stdout="", stderr="build failed", returncode=1)

    with pytest.raises(FlakeRefRealisationError, match="build failed"):
        try_resolve_flakeref(
            "/tmp/my flake#pkg",
            force_realise=True,
            exec_cmd_fn=fake_exec_cmd,
        )


def test_try_resolve_flakeref_raises_on_failed_eval_for_flakeref():
    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout="", stderr="attribute missing", returncode=1)

    with pytest.raises(FlakeRefResolutionError, match="attribute missing"):
        try_resolve_flakeref(".#missing", exec_cmd_fn=fake_exec_cmd)


def test_try_resolve_flakeref_returns_none_for_non_flake_path():
    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(
            stdout="",
            stderr="does not contain a 'flake.nix'",
            returncode=1,
        )

    resolved = try_resolve_flakeref(
        "/nix/store/not-a-flake-output",
        exec_cmd_fn=fake_exec_cmd,
    )

    assert resolved is None


@given(PLAIN_MISSING_PATHS)
def test_try_resolve_flakeref_returns_none_for_generated_plain_paths(path):
    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout="", stderr="dummy eval failure", returncode=1)

    resolved = try_resolve_flakeref(path, exec_cmd_fn=fake_exec_cmd)

    assert resolved is None


@pytest.mark.parametrize("path", ["missing", "./missing", "foo/bar"])
def test_try_resolve_flakeref_returns_none_for_missing_relative_paths(path):
    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout="", stderr="dummy eval failure", returncode=1)

    resolved = try_resolve_flakeref(path, exec_cmd_fn=fake_exec_cmd)

    assert resolved is None


def test_try_resolve_flakeref_returns_none_for_existing_fragment_path_when_eval_fails(
    tmp_path,
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

    resolved = try_resolve_flakeref(existing_path.as_posix(), exec_cmd_fn=fake_exec_cmd)

    assert resolved is None
    assert calls


@given(FLAKE_REFS)
def test_try_resolve_flakeref_raises_for_generated_flakeref_failures(flakeref):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout="", stderr="attribute missing", returncode=1)

    with pytest.raises(FlakeRefResolutionError, match="attribute missing"):
        try_resolve_flakeref(flakeref, exec_cmd_fn=fake_exec_cmd)

    assert flakeref in calls[0][0]
    assert calls[0][1] == {
        "raise_on_error": False,
        "return_error": True,
        "log_error": False,
    }


@given(FLAKE_REFS)
def test_try_resolve_flakeref_strips_generated_eval_output(flakeref):
    resolved_path = "/nix/store/00000000000000000000000000000000-package"

    def fake_exec_cmd(cmd, **_kwargs):
        assert flakeref in cmd
        return SimpleNamespace(stdout=f"{resolved_path}\n", stderr="", returncode=0)

    resolved = try_resolve_flakeref(flakeref, exec_cmd_fn=fake_exec_cmd)

    assert resolved == resolved_path


def test_flakeref_realisation_error_accepts_none_stderr():
    error = FlakeRefRealisationError(".#pkg", stderr=None)

    assert error.stderr == ""
    assert str(error) == "Failed force-realising flakeref '.#pkg'"


def test_flake_ref_resolution_error_preserves_stderr_verbatim():
    error = FlakeRefResolutionError(".#pkg", stderr="stderr details\n")

    assert error.stderr == "stderr details\n"
    assert str(error) == "Failed evaluating flakeref '.#pkg': stderr details"
