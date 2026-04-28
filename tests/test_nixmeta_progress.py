#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for nixmeta progress logging."""

import json
import subprocess
from types import SimpleNamespace

from nixmeta import flake_metadata
from nixmeta import main as nixmeta_main
from nixmeta import scanner as nixmeta_scanner


class CapturingLogger:
    def __init__(self):
        self.records = []

    def debug(self, msg, *args):
        self.records.append(("debug", msg, args))

    def info(self, msg, *args):
        self.records.append(("info", msg, args))

    def warning(self, msg, *args):
        self.records.append(("warning", msg, args))

    def fatal(self, msg, *args):
        self.records.append(("fatal", msg, args))

    def log(self, level, msg, *args):
        self.records.append(("log", level, msg, args))


def test_nixmeta_main_logs_scan_start(monkeypatch):
    args = SimpleNamespace(
        flakeref="github:NixOS/nixpkgs?ref=nixos-unstable",
        out="nixmeta.csv",
        append=False,
    )
    logger = CapturingLogger()
    events = []

    class FakeScanner:
        def scan(self, flakeref):
            events.append(("scan", flakeref))

        def to_csv(self, out, append):
            events.append(("to_csv", out, append))

    monkeypatch.setattr(nixmeta_main, "LOG", logger)
    monkeypatch.setattr(
        nixmeta_main,
        "exit_unless_command_exists",
        lambda command: events.append(("command", command)),
    )
    monkeypatch.setattr(nixmeta_main, "NixMetaScanner", FakeScanner)

    nixmeta_main._run(args)

    assert (
        "info",
        "Scanning nixpkgs metadata for '%s'",
        ("github:NixOS/nixpkgs?ref=nixos-unstable",),
    ) in logger.records
    assert events == [
        ("command", "nix"),
        ("command", "nix-env"),
        ("scan", "github:NixOS/nixpkgs?ref=nixos-unstable"),
        ("to_csv", "nixmeta.csv", False),
    ]


def test_get_flake_metadata_logs_metadata_read():
    logger = CapturingLogger()

    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout='{"path": "/nix/store/nixpkgs"}', returncode=0)

    meta = flake_metadata.get_flake_metadata(
        "nixpkgs=/tmp/my flake",
        exec_cmd_fn=fake_exec_cmd,
        log=logger,
    )

    assert meta == {"path": "/nix/store/nixpkgs"}
    assert (
        "info",
        "Reading flake metadata for '%s'",
        ("/tmp/my flake",),
    ) in logger.records


def test_get_nixpkgs_flakeref_uses_root_nixpkgs_input_with_renamed_node():
    meta_json = {
        "locks": {
            "root": "root",
            "nodes": {
                "root": {"inputs": {"nixpkgs": "nixpkgs_3"}},
                "nixpkgs": {
                    "locked": {
                        "type": "github",
                        "owner": "NixOS",
                        "repo": "nixpkgs",
                        "rev": "wrong",
                    }
                },
                "nixpkgs_3": {
                    "locked": {
                        "type": "github",
                        "owner": "NixOS",
                        "repo": "nixpkgs",
                        "rev": "right",
                    }
                },
            },
        }
    }

    assert (
        flake_metadata.get_nixpkgs_flakeref(meta_json)
        == "github:NixOS/nixpkgs?rev=right"
    )


def test_nixmeta_scanner_logs_nix_env_progress(tmp_path, monkeypatch):
    nixpkgs_path = tmp_path / "nixpkgs"
    nixpkgs_path.mkdir()
    logger = CapturingLogger()
    commands = []

    def fake_run_nix_env_metadata(_cmd, stdout):
        commands.append(_cmd)
        stdout.write(
            json.dumps(
                {
                    "hello": {
                        "name": "hello-2.12.1",
                        "pname": "hello",
                        "version": "2.12.1",
                        "meta": {
                            "homepage": "https://example.invalid/hello",
                            "unfree": False,
                            "description": "GNU hello",
                            "position": "pkgs/tools/misc/hello/default.nix:1",
                            "license": {
                                "shortName": "GPLv3+",
                                "spdxId": "GPL-3.0-or-later",
                            },
                            "maintainers": {
                                "email": "maintainer@example.invalid",
                            },
                        },
                    }
                }
            ).encode("utf-8")
        )
        stdout.flush()

    monkeypatch.setattr(nixmeta_scanner, "LOG", logger)
    monkeypatch.setattr(
        nixmeta_scanner,
        "nixref_to_nixpkgs_path",
        lambda *_args, **_kwargs: nixpkgs_path,
    )
    monkeypatch.setattr(
        nixmeta_scanner,
        "_run_nix_env_metadata",
        fake_run_nix_env_metadata,
    )

    scanner = nixmeta_scanner.NixMetaScanner()
    scanner.scan("github:NixOS/nixpkgs?ref=nixos-unstable")

    assert (
        "info",
        "Reading nixpkgs metadata from '%s'",
        (nixpkgs_path.as_posix(),),
    ) in logger.records
    assert ("info", "Parsing nixpkgs metadata", ()) in logger.records
    assert commands
    assert scanner.to_df() is not None


def test_run_nix_env_metadata_captures_successful_stderr(monkeypatch, tmp_path):
    calls = []
    logger = CapturingLogger()

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stderr="warning: noisy eval\n")

    monkeypatch.setattr(nixmeta_scanner.subprocess, "run", fake_run)
    monkeypatch.setattr(nixmeta_scanner, "LOG", logger)
    out_path = tmp_path / "meta.json"

    with out_path.open("w", encoding="utf-8") as out:
        nixmeta_scanner._run_nix_env_metadata(["nix-env"], stdout=out)

    assert calls
    assert calls[0][1]["stderr"] is subprocess.PIPE
    assert calls[0][1]["stdout"].name == out_path.as_posix()
    assert (
        "debug",
        "nix-env metadata stderr:\n%s",
        ("warning: noisy eval",),
    ) in logger.records


def test_nixmeta_scanner_tolerates_empty_metadata_json(tmp_path, monkeypatch):
    nixpkgs_path = tmp_path / "nixpkgs"
    nixpkgs_path.mkdir()

    def fake_run_nix_env_metadata(_cmd, stdout):
        stdout.write(b"{}")
        stdout.flush()

    monkeypatch.setattr(
        nixmeta_scanner,
        "_run_nix_env_metadata",
        fake_run_nix_env_metadata,
    )

    scanner = nixmeta_scanner.NixMetaScanner()
    scanner.scan_path(nixpkgs_path)

    assert scanner.to_df() is not None
    assert scanner.to_df().empty


def test_nixmeta_expression_scan_enables_flakes(monkeypatch):
    commands = []

    def fake_run_nix_env_metadata(cmd, stdout):
        commands.append(cmd)
        stdout.write(b"{}")
        stdout.flush()

    monkeypatch.setattr(
        nixmeta_scanner,
        "_run_nix_env_metadata",
        fake_run_nix_env_metadata,
    )

    scanner = nixmeta_scanner.NixMetaScanner()
    scanner.scan_expression('builtins.getFlake "github:NixOS/nixpkgs"')

    assert commands
    assert [
        "--option",
        "experimental-features",
        "nix-command flakes",
    ] in [commands[0][idx : idx + 3] for idx in range(len(commands[0]) - 2)]


def test_nixmeta_expression_scan_honors_impure(monkeypatch):
    commands = []

    def fake_run_nix_env_metadata(cmd, stdout):
        commands.append(cmd)
        stdout.write(b"{}")
        stdout.flush()

    monkeypatch.setattr(
        nixmeta_scanner,
        "_run_nix_env_metadata",
        fake_run_nix_env_metadata,
    )

    scanner = nixmeta_scanner.NixMetaScanner()
    scanner.scan_expression(
        'builtins.getFlake "path:/tmp/local-flake"',
        impure=True,
    )

    assert commands
    assert "--impure" in commands[0]
