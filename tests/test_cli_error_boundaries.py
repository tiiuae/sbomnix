#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for CLI error-to-exit-code boundaries."""

from types import SimpleNamespace

import pytest

from common.errors import SbomnixError
from nixgraph import main as nixgraph_main
from nixmeta import main as nixmeta_main
from nixupdate import nix_outdated
from provenance import main as provenance_main
from vulnxscan import osv as osv_cli
from vulnxscan import vulnxscan_cli


def test_vulnxscan_invalid_sbom_exits_nonzero(tmp_path, monkeypatch):
    invalid_sbom = tmp_path / "invalid.json"
    invalid_sbom.write_text("not json", encoding="utf-8")

    args = SimpleNamespace(
        TARGET=invalid_sbom.as_posix(),
        verbose=0,
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
        verbose=0,
        out="osv.csv",
        ecosystems="GIT",
    )
    monkeypatch.setattr(osv_cli, "getargs", lambda: args)
    monkeypatch.setattr(osv_cli, "set_log_verbosity", lambda _verbosity: None)

    with pytest.raises(SystemExit) as excinfo:
        osv_cli.main()

    assert excinfo.value.code == 1


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
                verbose=0,
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
                verbose=0,
            ),
            lambda monkeypatch: None,
            "resolve_nix_target",
        ),
        (
            vulnxscan_cli,
            SimpleNamespace(
                TARGET=".#broken",
                verbose=0,
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
                verbose=0,
            ),
            lambda monkeypatch: None,
            "exit_unless_command_exists",
        ),
        (
            provenance_main,
            SimpleNamespace(
                target="/nix/store/broken.drv",
                recursive=False,
                out=None,
                verbose=0,
            ),
            lambda monkeypatch: monkeypatch.setattr(
                provenance_main,
                "get_env_metadata",
                lambda: provenance_main.BuildMeta("", "", "", "", "", "{}", "{}"),
            ),
            "provenance",
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
