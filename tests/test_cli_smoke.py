#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-class-docstring,missing-function-docstring

"""Offline smoke tests for lightweight CLI entrypoint boundaries."""

from types import SimpleNamespace

import pandas as pd

from common.df import df_from_csv_file
from repology import repology_cve
from vulnxscan import osv as osv_cli


def test_repology_cve_main_writes_output_csv(tmp_path, monkeypatch):
    out_path = tmp_path / "repology_cves.csv"
    reported = []

    monkeypatch.setattr(
        repology_cve,
        "getargs",
        lambda: SimpleNamespace(
            PKG_NAME="openssl",
            PKG_VERSION="3.1.0",
            out=out_path.as_posix(),
            verbose=0,
        ),
    )
    monkeypatch.setattr(repology_cve, "set_log_verbosity", lambda _verbosity: None)
    monkeypatch.setattr(
        repology_cve,
        "query_cve",
        lambda pkg_name, pkg_version: pd.DataFrame(
            [
                {
                    "package": pkg_name,
                    "version": pkg_version,
                    "cve": "CVE-2024-1111",
                }
            ]
        ),
    )
    monkeypatch.setattr(
        repology_cve,
        "report_cves",
        lambda df: reported.append(df.copy(deep=True)) or True,
    )

    repology_cve.main()

    assert len(reported) == 1
    assert df_from_csv_file(out_path).to_dict(orient="records") == [
        {
            "package": "openssl",
            "version": "3.1.0",
            "cve": "CVE-2024-1111",
        }
    ]


def test_osv_main_writes_output_csv_with_requested_ecosystems(tmp_path, monkeypatch):
    sbom_path = tmp_path / "sbom.cdx.json"
    out_path = tmp_path / "osv.csv"
    sbom_path.write_text(
        '{"metadata":{"component":{"name":"hello","version":"1.0"}},"components":[]}',
        encoding="utf-8",
    )

    class FakeOSV:
        def __init__(self):
            self.calls = []

        def query_vulns(self, sbom, ecosystems):
            self.calls.append((sbom, ecosystems))

        def to_dataframe(self):
            return pd.DataFrame(
                [
                    {
                        "vuln_id": "OSV-1",
                        "modified": "2024-01-01",
                        "package": "hello",
                        "version": "1.0",
                    }
                ]
            )

    fake_osv = FakeOSV()
    monkeypatch.setattr(
        osv_cli,
        "getargs",
        lambda: SimpleNamespace(
            SBOM=sbom_path,
            ecosystems="GIT, OSS-Fuzz",
            out=out_path.as_posix(),
            verbose=0,
        ),
    )
    monkeypatch.setattr(osv_cli, "set_log_verbosity", lambda _verbosity: None)
    monkeypatch.setattr(osv_cli, "OSV", lambda: fake_osv)

    osv_cli.main()

    assert fake_osv.calls == [(sbom_path.as_posix(), ["GIT", "OSS-Fuzz"])]
    assert df_from_csv_file(out_path).to_dict(orient="records") == [
        {
            "vuln_id": "OSV-1",
            "modified": "2024-01-01",
            "package": "hello",
            "version": "1.0",
        }
    ]
