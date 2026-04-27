#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-class-docstring,missing-function-docstring

"""Tests for temporary SBOM and vulnerability-enrichment artifacts."""

import uuid
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from sbomnix import cli_utils as sbomnix_cli_utils
from sbomnix import main as sbomnix_main
from sbomnix import vuln_enrichment as sbomnix_vuln_enrichment
from sbomnix.sbomdb import SbomDb
from vulnxscan import vulnxscan_cli


def test_sbomnix_main_enriches_cdx_explicitly_when_include_vulns_is_set(monkeypatch):
    args = SimpleNamespace(
        NIXREF=".#target",
        buildtime=False,
        depth=None,
        verbose=1,
        include_vulns=True,
        exclude_meta=False,
        exclude_cpe_matching=False,
        csv=None,
        cdx="sbom.cdx.json",
        spdx=None,
        impure=False,
    )
    events = []

    class FakeSbomDb:
        def __init__(self, **kwargs):
            events.append(("init", kwargs))

        def to_cdx_data(self):
            events.append(("to_cdx_data",))
            return {"bomFormat": "CycloneDX"}

        def enrich_cdx_with_vulnerabilities(self, cdx):
            events.append(("enrich", dict(cdx)))
            cdx["vulnerabilities"] = []

        def write_json(self, path, data, printinfo=False):
            events.append(("write_json", path, dict(data), printinfo))

        def to_spdx(self, _path):
            raise AssertionError("to_spdx should not run in this test")

        def to_csv(self, _path):
            raise AssertionError("to_csv should not run in this test")

    monkeypatch.setattr(sbomnix_main, "getargs", lambda: args)
    monkeypatch.setattr(sbomnix_main, "set_log_verbosity", lambda _verbosity: None)
    monkeypatch.setattr(
        sbomnix_main,
        "resolve_nix_target",
        lambda *_args, **_kwargs: sbomnix_cli_utils.ResolvedNixTarget(
            path="/nix/store/target",
            flakeref=".#target",
        ),
    )
    monkeypatch.setattr(sbomnix_main, "SbomDb", FakeSbomDb)

    sbomnix_main.main()

    assert events == [
        (
            "init",
            {
                "nix_path": "/nix/store/target",
                "buildtime": False,
                "depth": None,
                "flakeref": ".#target",
                "include_meta": True,
                "include_vulns": True,
                "include_cpe": True,
            },
        ),
        ("to_cdx_data",),
        ("enrich", {"bomFormat": "CycloneDX"}),
        (
            "write_json",
            "sbom.cdx.json",
            {"bomFormat": "CycloneDX", "vulnerabilities": []},
            True,
        ),
    ]


def test_vulnxscan_cleans_generated_tempfiles_on_failure(tmp_path, monkeypatch):
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


def test_to_cdx_no_longer_triggers_vulnerability_scans(tmp_path, monkeypatch):
    seen_calls = []

    def no_dependencies(_self, _drv, **_kwargs):
        return None

    class FailIfCalledScanner:
        def __init__(self):
            seen_calls.append("init")

        def scan_vulnix(self, _target_path, _buildtime):
            raise AssertionError("scan_vulnix should not run during plain export")

        def scan_grype(self, _sbom_path):
            raise AssertionError("scan_grype should not run during plain export")

        def scan_osv(self, _sbom_path):
            raise AssertionError("scan_osv should not run during plain export")

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

    monkeypatch.setattr("sbomnix.vuln_enrichment.VulnScan", FailIfCalledScanner)
    monkeypatch.setattr(SbomDb, "lookup_dependencies", no_dependencies)

    out_path = tmp_path / "out.cdx.json"
    sbomdb.to_cdx(out_path, printinfo=False)

    assert out_path.exists()
    assert not seen_calls


def test_sbomdb_vuln_tempfile_is_removed_on_scan_failure(tmp_path, monkeypatch):
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
        sbomnix_vuln_enrichment,
        "NamedTemporaryFile",
        lambda **_kwargs: FakeTempFile(temp_cdx_path),
    )
    monkeypatch.setattr(sbomnix_vuln_enrichment, "VulnScan", FailingScanner)
    monkeypatch.setattr(SbomDb, "lookup_dependencies", no_dependencies)

    cdx = sbomdb.to_cdx_data()

    with pytest.raises(RuntimeError, match="osv scan failed"):
        sbomdb.enrich_cdx_with_vulnerabilities(cdx)

    assert seen_paths == [temp_cdx_path, temp_cdx_path]
    assert not temp_cdx_path.exists()
