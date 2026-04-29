#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for SBOM vulnerability enrichment boundaries."""

import uuid
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from common.errors import SbomnixError
from sbomnix import cli_utils as sbomnix_cli_utils
from sbomnix import main as sbomnix_main
from sbomnix import vuln_enrichment as sbomnix_vuln_enrichment
from sbomnix.builder import SbomBuilder


class CapturingLogger:
    def __init__(self):
        self.records = []

    def info(self, msg, *args):
        self.records.append(("info", msg, args))

    def fatal(self, msg, *args):
        self.records.append(("fatal", msg, args))


def test_sbomnix_getargs_accepts_meta_nixpkgs():
    args = sbomnix_main.getargs(
        [
            "/nix/store/target",
            "--meta-nixpkgs",
            "nix-path",
        ]
    )

    assert args.meta_nixpkgs == "nix-path"


def test_sbomnix_run_rejects_exclude_meta_with_meta_nixpkgs():
    args = SimpleNamespace(
        NIXREF="/nix/store/target",
        buildtime=False,
        depth=None,
        verbose=0,
        include_vulns=False,
        exclude_meta=True,
        meta_nixpkgs="nix-path",
        exclude_cpe_matching=False,
        csv=None,
        cdx=None,
        spdx=None,
        impure=True,
    )

    with pytest.raises(SbomnixError, match="--exclude-meta"):
        sbomnix_main._run(args)


def test_sbomnix_main_enriches_cdx_explicitly_when_include_vulns_is_set(monkeypatch):
    args = SimpleNamespace(
        NIXREF=".#target",
        buildtime=False,
        depth=None,
        verbose=0,
        include_vulns=True,
        exclude_meta=False,
        meta_nixpkgs=None,
        exclude_cpe_matching=False,
        csv=None,
        cdx="sbom.cdx.json",
        spdx=None,
        impure=True,
    )
    events = []

    class FakeSbomBuilder:
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
    monkeypatch.setattr(sbomnix_main, "SbomBuilder", FakeSbomBuilder)

    sbomnix_main.main()

    assert events == [
        (
            "init",
            {
                "nix_path": "/nix/store/target",
                "buildtime": False,
                "depth": None,
                "flakeref": ".#target",
                "original_ref": None,
                "meta_nixpkgs": None,
                "impure": True,
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


def test_sbomnix_main_logs_generation_before_initializing_builder(monkeypatch):
    args = SimpleNamespace(
        NIXREF=".#target",
        buildtime=False,
        depth=None,
        verbose=0,
        include_vulns=False,
        exclude_meta=False,
        meta_nixpkgs=None,
        exclude_cpe_matching=False,
        csv=None,
        cdx=None,
        spdx=None,
        impure=False,
    )
    logger = CapturingLogger()
    events = []

    class FakeSbomBuilder:
        def __init__(self, **kwargs):
            events.append(("init", kwargs))

    monkeypatch.setattr(sbomnix_main, "LOG", logger)
    monkeypatch.setattr(
        sbomnix_main,
        "resolve_nix_target",
        lambda *_args, **_kwargs: sbomnix_cli_utils.ResolvedNixTarget(
            path="/nix/store/target",
            flakeref=".#target",
        ),
    )
    monkeypatch.setattr(sbomnix_main, "SbomBuilder", FakeSbomBuilder)

    sbomnix_main._run(args)

    assert logger.records == [
        ("info", "Generating SBOM for target '%s'", ("/nix/store/target",))
    ]
    assert events == [
        (
            "init",
            {
                "nix_path": "/nix/store/target",
                "buildtime": False,
                "depth": None,
                "flakeref": ".#target",
                "original_ref": None,
                "meta_nixpkgs": None,
                "impure": False,
                "include_meta": True,
                "include_vulns": False,
                "include_cpe": True,
            },
        )
    ]


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

    # Bypass __init__ to keep the test focused on export behavior without Nix IO.
    sbomdb = object.__new__(SbomBuilder)
    sbomdb.uid = "store_path"
    sbomdb.nix_path = "/nix/store/target"
    sbomdb.buildtime = False
    sbomdb.target_deriver = "/nix/store/target.drv"
    sbomdb.target_component_ref = "/nix/store/target.drv"
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
    monkeypatch.setattr(SbomBuilder, "lookup_dependencies", no_dependencies)

    out_path = tmp_path / "out.cdx.json"
    sbomdb.to_cdx(out_path, printinfo=False)

    assert out_path.exists()
    assert not seen_calls


@pytest.mark.parametrize(
    ("buildtime", "expected_target"),
    [
        (False, "/nix/store/target-output"),
        (True, "/nix/store/target.drv"),
    ],
)
def test_sbom_vuln_enrichment_scans_expected_nix_target(
    buildtime,
    expected_target,
    monkeypatch,
):
    seen_vulnix_calls = []

    class CapturingScanner:
        def __init__(self):
            self.df_grype = pd.DataFrame()
            self.df_osv = pd.DataFrame()
            self.df_vulnix = pd.DataFrame()

        def scan_vulnix(self, target_path, scan_buildtime):
            seen_vulnix_calls.append((target_path, scan_buildtime))

        def scan_grype(self, _sbom_path):
            return None

        def scan_osv(self, _sbom_path):
            return None

    # Bypass __init__ to keep the test focused on enrichment target selection.
    sbomdb = object.__new__(SbomBuilder)
    sbomdb.nix_path = "/nix/store/target-output"
    sbomdb.buildtime = buildtime
    sbomdb.target_deriver = "/nix/store/target.drv"
    sbomdb.target_component_ref = "/nix/store/target.drv"
    sbomdb.df_sbomdb = pd.DataFrame()

    monkeypatch.setattr(sbomnix_vuln_enrichment, "VulnScan", CapturingScanner)

    cdx = {"bomFormat": "CycloneDX"}

    sbomdb.enrich_cdx_with_vulnerabilities(cdx)

    assert seen_vulnix_calls == [(expected_target, buildtime)]
    assert cdx["vulnerabilities"] == []


def test_sbom_vuln_tempfile_is_removed_on_scan_failure(tmp_path, monkeypatch):
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

    # Bypass __init__ to keep the test focused on enrichment tempfile cleanup.
    sbomdb = object.__new__(SbomBuilder)
    sbomdb.uid = "store_path"
    sbomdb.nix_path = "/nix/store/target"
    sbomdb.buildtime = False
    sbomdb.target_deriver = "/nix/store/target.drv"
    sbomdb.target_component_ref = "/nix/store/target.drv"
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
    monkeypatch.setattr(SbomBuilder, "lookup_dependencies", no_dependencies)

    cdx = sbomdb.to_cdx_data()

    with pytest.raises(RuntimeError, match="osv scan failed"):
        sbomdb.enrich_cdx_with_vulnerabilities(cdx)

    assert seen_paths == [temp_cdx_path, temp_cdx_path]
    assert not temp_cdx_path.exists()
