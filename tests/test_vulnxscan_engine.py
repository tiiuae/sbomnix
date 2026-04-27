#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for vulnxscan parser and reporting helpers."""

from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from vulnxscan.parsers import parse_grype_json, parse_vulnix_json
from vulnxscan.reporting import build_report_dataframe, write_reports
from vulnxscan.vulnscan import VulnScan


def test_parse_vulnix_json_updates_cvss_cache():
    """Populate vulnerability rows and severity cache from vulnix JSON."""
    cvss_cache = {}

    df = parse_vulnix_json(
        '[{"pname":"hello","version":"1.0","affected_by":["CVE-1"],'
        '"cvssv3_basescore":{"CVE-1":"7.5"}}]',
        cvss_cache=cvss_cache,
    )

    assert df.to_dict("records") == [
        {
            "package": "hello",
            "version": "1.0",
            "vuln_id": "CVE-1",
            "severity": "7.5",
            "scanner": "vulnix",
        }
    ]
    assert cvss_cache == {"CVE-1": "7.5"}


def test_parse_grype_json_prefers_cvss_v3_scores():
    """Select CVSS v3 severity when grype reports multiple CVSS entries."""
    cvss_cache = {}
    json_str = """
    {
      "matches": [
        {
          "artifact": {"name": "hello", "version": "1.0"},
          "vulnerability": {
            "id": "CVE-2",
            "cvss": [
              {"version": "2.0", "metrics": {"baseScore": 4.0}},
              {"version": "3.1", "metrics": {"baseScore": 9.8}}
            ]
          }
        }
      ]
    }
    """

    df = parse_grype_json(json_str, cvss_cache=cvss_cache)

    assert df.to_dict("records") == [
        {
            "package": "hello",
            "version": "1.0",
            "vuln_id": "CVE-2",
            "severity": 9.8,
            "scanner": "grype",
        }
    ]
    assert cvss_cache == {"CVE-2": 9.8}


def test_build_report_dataframe_merges_scanner_counts():
    """Aggregate scanner findings into the final report layout."""
    df_report = build_report_dataframe(
        df_vulnix=pd.DataFrame(
            [
                {
                    "package": "hello",
                    "version": "1.0",
                    "vuln_id": "CVE-1",
                    "severity": "7.5",
                    "scanner": "vulnix",
                }
            ]
        ),
        df_grype=pd.DataFrame(
            [
                {
                    "package": "hello",
                    "version": "1.0",
                    "vuln_id": "CVE-1",
                    "severity": "7.5",
                    "scanner": "grype",
                }
            ]
        ),
        df_osv=pd.DataFrame(),
    )

    assert df_report.to_dict("records") == [
        {
            "vuln_id": "CVE-1",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-1",
            "package": "hello",
            "version": "1.0",
            "severity": "7.5",
            "grype": "1",
            "osv": "0",
            "vulnix": "1",
            "sum": 2,
            "sortcol": df_report.iloc[0]["sortcol"],
        }
    ]


def test_write_reports_writes_triage_report(tmp_path):
    """Write both the main report and the derived triage report files."""
    main_out = tmp_path / "vulns.csv"
    df_report = pd.DataFrame([{"vuln_id": "CVE-1"}])
    df_triaged = pd.DataFrame([{"vuln_id": "CVE-1", "classify": "triaged"}])

    write_reports(df_report, main_out, df_triaged=df_triaged)

    assert main_out.exists()
    assert (tmp_path / "vulns.triage.csv").exists()
    assert Path(main_out).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("buildtime", "expected_cmd"),
    [
        (False, ["vulnix", "/nix/store/my target", "-C", "--json"]),
        (True, ["vulnix", "/nix/store/my target", "--json"]),
    ],
)
def test_scan_vulnix_uses_argv_lists(monkeypatch, buildtime, expected_cmd):
    """Build vulnix subprocess argv without splitting whitespace-containing paths."""
    calls = []
    parsed = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(
            stdout='[{"pname": "hello", "version": "1.0", "affected_by": []}]',
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr("vulnxscan.vulnscan.exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        VulnScan,
        "_parse_vulnix",
        lambda self, stdout: parsed.append(stdout),
    )

    VulnScan().scan_vulnix("/nix/store/my target", buildtime=buildtime)

    assert calls == [
        (
            expected_cmd,
            {"raise_on_error": False, "return_error": True, "log_error": False},
        )
    ]
    assert parsed == ['[{"pname": "hello", "version": "1.0", "affected_by": []}]']
