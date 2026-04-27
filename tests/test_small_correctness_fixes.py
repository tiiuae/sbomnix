#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-function-docstring

"""Targeted unit tests for small correctness fixes."""

from types import SimpleNamespace

import pytest

from common.errors import (
    FlakeRefRealisationError,
    FlakeRefResolutionError,
    SbomnixError,
)
from nixgraph import main as nixgraph_main
from nixmeta import main as nixmeta_main
from nixupdate import nix_outdated
from sbomnix import cli_utils as sbomnix_cli_utils
from vulnxscan import osv as osv_cli
from vulnxscan import vulnxscan_cli


def test_vulnxscan_invalid_sbom_exits_nonzero(tmp_path, monkeypatch):
    invalid_sbom = tmp_path / "invalid.json"
    invalid_sbom.write_text("not json", encoding="utf-8")

    args = SimpleNamespace(
        TARGET=invalid_sbom.as_posix(),
        verbose=1,
        out="vulns.csv",
        buildtime=False,
        sbom=True,
        whitelist=None,
        triage=False,
        nixprs=False,
    )
    monkeypatch.setattr(vulnxscan_cli, "getargs", lambda: args)
    monkeypatch.setattr(vulnxscan_cli, "set_log_verbosity", lambda _verbosity: None)
    monkeypatch.setattr(
        vulnxscan_cli, "exit_unless_command_exists", lambda _command: None
    )

    with pytest.raises(SystemExit) as excinfo:
        vulnxscan_cli.main()

    assert excinfo.value.code == 1


def test_osv_invalid_sbom_exits_nonzero(tmp_path, monkeypatch):
    missing_sbom = tmp_path / "missing.json"
    args = SimpleNamespace(
        SBOM=missing_sbom,
        verbose=1,
        out="osv.csv",
        ecosystems="GIT",
    )
    monkeypatch.setattr(osv_cli, "getargs", lambda: args)
    monkeypatch.setattr(osv_cli, "set_log_verbosity", lambda _verbosity: None)

    with pytest.raises(SystemExit) as excinfo:
        osv_cli.main()

    assert excinfo.value.code == 1


def test_resolve_nix_target_preserves_flakeref_on_success(monkeypatch):
    monkeypatch.setattr(
        sbomnix_cli_utils,
        "try_resolve_flakeref",
        lambda *_args, **_kwargs: "/nix/store/resolved",
    )

    resolved = sbomnix_cli_utils.resolve_nix_target(".#hello", buildtime=False)

    assert resolved == sbomnix_cli_utils.ResolvedNixTarget(
        path="/nix/store/resolved",
        flakeref=".#hello",
    )


def test_resolve_nix_target_propagates_flakeref_realisation_failure_without_store_fallback(
    monkeypatch,
):
    artifact_checks = []

    def raise_realisation_error(*_args, **_kwargs):
        raise FlakeRefRealisationError(".#broken", "build failed")

    monkeypatch.setattr(
        sbomnix_cli_utils,
        "try_resolve_flakeref",
        raise_realisation_error,
    )
    monkeypatch.setattr(
        sbomnix_cli_utils,
        "exit_unless_nix_artifact",
        lambda path, force_realise=False: artifact_checks.append((path, force_realise)),
    )

    with pytest.raises(FlakeRefRealisationError) as excinfo:
        sbomnix_cli_utils.resolve_nix_target(".#broken", buildtime=False)

    assert (
        str(excinfo.value) == "Failed force-realising flakeref '.#broken': build failed"
    )
    assert not artifact_checks


def test_resolve_nix_target_propagates_flakeref_eval_failure_without_store_fallback(
    monkeypatch,
):
    artifact_checks = []

    def raise_resolution_error(*_args, **_kwargs):
        raise FlakeRefResolutionError(".#broken", "attribute missing")

    monkeypatch.setattr(
        sbomnix_cli_utils,
        "try_resolve_flakeref",
        raise_resolution_error,
    )
    monkeypatch.setattr(
        sbomnix_cli_utils,
        "exit_unless_nix_artifact",
        lambda path, force_realise=False: artifact_checks.append((path, force_realise)),
    )

    with pytest.raises(FlakeRefResolutionError) as excinfo:
        sbomnix_cli_utils.resolve_nix_target(".#broken", buildtime=False)

    assert (
        str(excinfo.value) == "Failed evaluating flakeref '.#broken': attribute missing"
    )
    assert not artifact_checks


def test_resolve_nix_target_falls_back_to_store_path_validation(monkeypatch):
    artifact_checks = []

    monkeypatch.setattr(
        sbomnix_cli_utils,
        "try_resolve_flakeref",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        sbomnix_cli_utils,
        "exit_unless_nix_artifact",
        lambda path, force_realise=False: artifact_checks.append((path, force_realise)),
    )

    resolved = sbomnix_cli_utils.resolve_nix_target("/nix/store/not-a-flake")

    assert resolved == sbomnix_cli_utils.ResolvedNixTarget(
        path="/nix/store/not-a-flake",
        flakeref=None,
    )
    assert artifact_checks == [("/nix/store/not-a-flake", True)]


@pytest.mark.parametrize(
    ("module", "args", "prep", "patched_name"),
    [
        (
            nix_outdated,
            SimpleNamespace(
                NIXREF=".#broken",
                buildtime=False,
                local=False,
                out="nix_outdated.csv",
                verbose=1,
            ),
            lambda monkeypatch: None,
            "resolve_nix_target",
        ),
        (
            nixgraph_main,
            SimpleNamespace(
                NIXREF=".#broken",
                buildtime=False,
                depth=1,
                inverse=None,
                out="graph.png",
                colorize=None,
                until=None,
                pathnames=False,
                verbose=1,
            ),
            lambda monkeypatch: None,
            "resolve_nix_target",
        ),
        (
            vulnxscan_cli,
            SimpleNamespace(
                TARGET=".#broken",
                verbose=1,
                out="vulns.csv",
                buildtime=False,
                sbom=False,
                whitelist=None,
                triage=False,
                nixprs=False,
            ),
            lambda monkeypatch: monkeypatch.setattr(
                vulnxscan_cli, "exit_unless_command_exists", lambda _command: None
            ),
            "resolve_nix_target",
        ),
        (
            nixmeta_main,
            SimpleNamespace(
                flakeref="github:NixOS/nixpkgs?ref=nixos-unstable",
                out="nixmeta.csv",
                append=False,
                verbose=1,
            ),
            lambda monkeypatch: None,
            "exit_unless_command_exists",
        ),
    ],
)
def test_cli_translates_sbomnix_errors_to_exit_code_1(
    monkeypatch, module, args, prep, patched_name
):
    prep(monkeypatch)
    monkeypatch.setattr(module, "getargs", lambda: args, raising=False)
    monkeypatch.setattr(module, "_getargs", lambda: args, raising=False)
    monkeypatch.setattr(module, "set_log_verbosity", lambda _verbosity: None)
    monkeypatch.setattr(
        module,
        patched_name,
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            SbomnixError("expected failure")
        ),
    )

    with pytest.raises(SystemExit) as excinfo:
        module.main()

    assert excinfo.value.code == 1
