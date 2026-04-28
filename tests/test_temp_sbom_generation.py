#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for temporary SBOM generation and cleanup."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from sbomnix import cli_utils as sbomnix_cli_utils
from vulnxscan import vulnxscan_cli


def test_vulnxscan_cleans_generated_tempfiles_on_failure(tmp_path, monkeypatch):
    sbom_cdx_path = tmp_path / "generated.cdx.json"
    sbom_csv_path = tmp_path / "generated.csv"
    sbom_cdx_path.write_text("{}", encoding="utf-8")
    sbom_csv_path.write_text("", encoding="utf-8")

    args = SimpleNamespace(
        TARGET="target",
        verbose=0,
        out="vulns.csv",
        buildtime=False,
        sbom=False,
        whitelist=None,
        triage=False,
        nixprs=False,
    )

    class FailingScanner:
        def scan_vulnix(self, _target_path, _buildtime):
            return None

        def scan_grype(self, _sbom_path):
            raise RuntimeError("scan failed")

        def scan_osv(self, _sbom_path):
            raise AssertionError("scan_osv should not run after grype failure")

        def report(self, _args, _sbom_csv_path):
            raise AssertionError("report should not run after scan failure")

    monkeypatch.setattr(vulnxscan_cli, "getargs", lambda: args)
    monkeypatch.setattr(vulnxscan_cli, "set_log_verbosity", lambda _verbosity: None)
    monkeypatch.setattr(
        vulnxscan_cli, "exit_unless_command_exists", lambda _command: None
    )
    monkeypatch.setattr(
        vulnxscan_cli,
        "resolve_nix_target",
        lambda _target, buildtime=False: sbomnix_cli_utils.ResolvedNixTarget(
            path="/nix/store/target"
        ),
    )
    monkeypatch.setattr(
        vulnxscan_cli,
        "generate_temp_sbom",
        lambda _target_path, _buildtime, **_kwargs: sbomnix_cli_utils.GeneratedSbom(
            cdx_path=sbom_cdx_path,
            csv_path=sbom_csv_path,
        ),
    )
    monkeypatch.setattr(vulnxscan_cli, "VulnScan", FailingScanner)

    with pytest.raises(RuntimeError, match="scan failed"):
        vulnxscan_cli.main()

    assert not sbom_cdx_path.exists()
    assert not sbom_csv_path.exists()


def test_generate_temp_sbom_without_csv_returns_only_cdx_path(tmp_path, monkeypatch):
    sbom_cdx_path = tmp_path / "generated.cdx.json"

    class FakeTempFile:
        def __init__(self, path):
            self.name = path.as_posix()

        def __enter__(self):
            Path(self.name).touch()
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    class DummySbomDb:
        def __init__(self, _target_path, _buildtime, include_meta=False):
            assert include_meta is False

        def to_cdx(self, sbom_path, printinfo=False):
            Path(sbom_path).write_text("{}", encoding="utf-8")
            assert printinfo is False

        def to_csv(self, _sbom_path, loglevel=None):
            raise AssertionError("to_csv should not run when include_csv is False")

    monkeypatch.setattr(
        sbomnix_cli_utils,
        "NamedTemporaryFile",
        lambda **_kwargs: FakeTempFile(sbom_cdx_path),
    )
    monkeypatch.setattr(sbomnix_cli_utils, "SbomDb", DummySbomDb)

    generated = sbomnix_cli_utils.generate_temp_sbom(
        "/nix/store/target",
        buildtime=False,
        prefix="nixdeps_",
        cdx_suffix=".cdx.json",
    )

    assert generated == sbomnix_cli_utils.GeneratedSbom(
        cdx_path=sbom_cdx_path,
        csv_path=None,
    )
    assert sbom_cdx_path.exists()
    generated.cleanup()
    assert not sbom_cdx_path.exists()


def test_generate_temp_sbom_cleans_tempfiles_on_generation_failure(
    tmp_path, monkeypatch
):
    sbom_cdx_path = tmp_path / "generated.cdx.json"
    sbom_csv_path = tmp_path / "generated.csv"

    class FakeTempFile:
        def __init__(self, path):
            self.name = path.as_posix()

        def __enter__(self):
            Path(self.name).touch()
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    class FailingSbomDb:
        def __init__(self, _target_path, _buildtime, include_meta=False):
            assert include_meta is False

        def to_cdx(self, sbom_path, printinfo=False):
            Path(sbom_path).write_text("{}", encoding="utf-8")
            assert printinfo is False

        def to_csv(self, sbom_path, loglevel=None):
            Path(sbom_path).write_text("", encoding="utf-8")
            assert loglevel is not None
            raise RuntimeError("sbom csv generation failed")

    monkeypatch.setattr(
        sbomnix_cli_utils,
        "NamedTemporaryFile",
        lambda **kwargs: FakeTempFile(
            sbom_cdx_path if kwargs["suffix"] == ".json" else sbom_csv_path
        ),
    )
    monkeypatch.setattr(sbomnix_cli_utils, "SbomDb", FailingSbomDb)

    with pytest.raises(RuntimeError, match="sbom csv generation failed"):
        sbomnix_cli_utils.generate_temp_sbom(
            "/nix/store/target",
            buildtime=False,
            prefix="vulnxscan_",
            cdx_suffix=".json",
            include_csv=True,
        )

    assert not sbom_cdx_path.exists()
    assert not sbom_csv_path.exists()


def test_generate_temp_sbom_cleans_first_tempfile_if_second_creation_fails(
    tmp_path, monkeypatch
):
    sbom_cdx_path = tmp_path / "generated.cdx.json"

    class FakeTempFile:
        def __init__(self, path):
            self.name = path.as_posix()

        def __enter__(self):
            Path(self.name).touch()
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    class DummySbomDb:
        def __init__(self, _target_path, _buildtime, include_meta=False):
            assert include_meta is False

        def to_cdx(self, _sbom_path, printinfo=False):
            raise AssertionError("to_cdx should not run if csv tempfile creation fails")

        def to_csv(self, _sbom_path, loglevel=None):
            raise AssertionError("to_csv should not run if csv tempfile creation fails")

    def fake_named_temporary_file(**kwargs):
        if kwargs["suffix"] == ".json":
            return FakeTempFile(sbom_cdx_path)
        raise RuntimeError("csv tempfile creation failed")

    monkeypatch.setattr(
        sbomnix_cli_utils,
        "NamedTemporaryFile",
        fake_named_temporary_file,
    )
    monkeypatch.setattr(sbomnix_cli_utils, "SbomDb", DummySbomDb)

    with pytest.raises(RuntimeError, match="csv tempfile creation failed"):
        sbomnix_cli_utils.generate_temp_sbom(
            "/nix/store/target",
            buildtime=False,
            prefix="vulnxscan_",
            cdx_suffix=".json",
            include_csv=True,
        )

    assert not sbom_cdx_path.exists()
