#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-class-docstring,missing-function-docstring

"""Targeted unit tests for small correctness fixes"""

import uuid
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from common.utils import FlakeRefRealisationError, FlakeRefResolutionError, SbomnixError
from nixgraph import main as nixgraph_main
from nixmeta import main as nixmeta_main
from nixupdate import nix_outdated
from sbomnix import cli_utils as sbomnix_cli_utils
from sbomnix import main as sbomnix_main
from sbomnix.sbomdb import SbomDb
from vulnxscan import vulnxscan_cli


def test_vulnxscan_invalid_sbom_exits_nonzero(tmp_path, monkeypatch):
    """Invalid SBOM input should terminate with a failing exit code"""
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


def test_resolve_nix_target_preserves_flakeref_on_success(monkeypatch):
    """Resolved flakerefs should retain their original CLI reference."""
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
    """Flakeref build failures should not be misreported as invalid store paths."""
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
    """Flakeref eval failures should not be misreported as invalid store paths."""
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


@pytest.mark.parametrize(
    ("buildtime", "expected_force_realise"),
    [
        (False, True),
        (True, False),
    ],
)
def test_resolve_nix_target_falls_back_to_store_path_validation(
    tmp_path, monkeypatch, buildtime, expected_force_realise
):
    """Non-flakeref inputs should resolve to absolute store paths after validation."""
    artifact_checks = []
    target = tmp_path / "result"

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

    resolved = sbomnix_cli_utils.resolve_nix_target(
        target.as_posix(),
        buildtime=buildtime,
    )

    assert resolved == sbomnix_cli_utils.ResolvedNixTarget(
        path=target.resolve().as_posix(),
        flakeref=None,
    )
    assert artifact_checks == [(target.as_posix(), expected_force_realise)]


@pytest.mark.parametrize(
    ("module", "args", "prep", "patched_name"),
    [
        (
            sbomnix_main,
            SimpleNamespace(
                NIXREF=".#broken",
                buildtime=False,
                depth=None,
                verbose=1,
                include_vulns=False,
                exclude_meta=False,
                exclude_cpe_matching=False,
                csv=None,
                cdx=None,
                spdx=None,
                impure=False,
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


def test_vulnxscan_cleans_generated_tempfiles_on_failure(tmp_path, monkeypatch):
    """Generated SBOM temp files should be removed even when scanning fails"""
    sbom_cdx_path = tmp_path / "generated.cdx.json"
    sbom_csv_path = tmp_path / "generated.csv"
    sbom_cdx_path.write_text("{}", encoding="utf-8")
    sbom_csv_path.write_text("", encoding="utf-8")

    args = SimpleNamespace(
        TARGET="target",
        verbose=1,
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
    """The shared helper should support callers that only need a CDX artifact."""
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
    """Temp SBOM artifacts should be removed if SBOM generation fails."""
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
    """First temp artifact should not leak if creating the second one fails."""
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


def test_sbomdb_vuln_tempfile_is_removed_on_scan_failure(tmp_path, monkeypatch):
    """Temporary SBOM used for vulnerability enrichment should not leak"""
    temp_cdx_path = tmp_path / "vulnscan_temp.json"
    seen_paths = []

    def no_dependencies(_self, _drv, **_kwargs):
        return None

    class FakeTempFile:
        def __init__(self, path):
            self.name = path.as_posix()

        def __enter__(self):
            Path(self.name).touch()
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    class FailingScanner:
        def __init__(self):
            self.df_grype = pd.DataFrame()
            self.df_osv = pd.DataFrame()
            self.df_vulnix = pd.DataFrame()

        def scan_vulnix(self, _target_path, _buildtime):
            return None

        def scan_grype(self, sbom_path):
            sbom_path = Path(sbom_path)
            seen_paths.append(sbom_path)
            assert sbom_path.exists()

        def scan_osv(self, sbom_path):
            sbom_path = Path(sbom_path)
            seen_paths.append(sbom_path)
            raise RuntimeError("osv scan failed")

    sbomdb = object.__new__(SbomDb)
    sbomdb.uid = "store_path"
    sbomdb.buildtime = False
    sbomdb.target_deriver = "/nix/store/target.drv"
    sbomdb.depth = None
    sbomdb.uuid = uuid.uuid4()
    sbomdb.include_vulns = True
    sbomdb.sbom_type = "runtime_only"
    sbomdb.df_sbomdb = pd.DataFrame(
        [
            {
                "store_path": "/nix/store/target.drv",
                "pname": "target",
                "name": "target",
                "version": "1.0",
                "outputs": ["/nix/store/target"],
                "out": "/nix/store/target",
                "purl": "",
                "cpe": "",
                "urls": "",
                "patches": "",
            }
        ]
    )

    monkeypatch.setattr(
        "sbomnix.sbomdb.NamedTemporaryFile",
        lambda **_kwargs: FakeTempFile(temp_cdx_path),
    )
    monkeypatch.setattr("sbomnix.sbomdb.VulnScan", FailingScanner)
    monkeypatch.setattr(SbomDb, "_lookup_dependencies", no_dependencies)

    with pytest.raises(RuntimeError, match="osv scan failed"):
        sbomdb.to_cdx(tmp_path / "out.cdx.json", printinfo=False)

    assert seen_paths == [temp_cdx_path, temp_cdx_path]
    assert not temp_cdx_path.exists()
