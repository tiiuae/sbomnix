#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-class-docstring,missing-function-docstring
# pylint: disable=too-few-public-methods

"""Offline tests for nix_outdated pipeline and reporting behavior."""

import logging
from types import SimpleNamespace

import pandas as pd

from common.df import df_from_csv_file
from nixupdate import pipeline
from nixupdate.report import generate_report_df, write_report


class FakeSbomArtifact:
    def __init__(self, cdx_path):
        self.cdx_path = cdx_path
        self.cleaned = False

    def cleanup(self):
        self.cleaned = True


def _repology_df():
    return pd.DataFrame(
        [
            {
                "package": "hello",
                "version": "2.11",
                "version_sbom": "2.10",
                "newest_upstream_release": "2.12",
                "status": "outdated",
                "repo_version_classify": "repo_pkg_needs_update",
                "sbom_version_classify": "sbom_pkg_needs_update",
            }
        ]
    )


def test_collect_outdated_scan_data_runtime_uses_hooks_and_cleans_outputs(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(pipeline.LOG, "level", logging.INFO)
    artifact = FakeSbomArtifact(tmp_path / "deps.cdx.json")
    graph_csv = tmp_path / "graph.csv"
    calls = []

    def generate_temp_sbom(target_path, buildtime, prefix, cdx_suffix):
        calls.append(("generate_temp_sbom", target_path, buildtime, prefix, cdx_suffix))
        return artifact

    def query_repology(sbom_path):
        calls.append(("query_repology", sbom_path))
        return _repology_df()

    def run_nix_visualize(target_path):
        calls.append(("run_nix_visualize", target_path))
        graph_csv.write_text("package,version,level\nhello,2.10,1\n", encoding="utf-8")
        return graph_csv

    def parse_nix_visualize(csv_path):
        calls.append(("parse_nix_visualize", csv_path, csv_path.exists()))
        return pd.DataFrame(
            [
                {
                    "package": "hello",
                    "version": "2.10",
                    "level": "1",
                }
            ]
        )

    data = pipeline.collect_outdated_scan_data(
        "/nix/store/root",
        buildtime=False,
        hooks=pipeline.OutdatedScanHooks(
            query_repology=query_repology,
            generate_temp_sbom=generate_temp_sbom,
            run_nix_visualize=run_nix_visualize,
            parse_nix_visualize=parse_nix_visualize,
        ),
    )

    assert calls == [
        ("generate_temp_sbom", "/nix/store/root", False, "nixdeps_", ".cdx.json"),
        ("query_repology", artifact.cdx_path),
        ("run_nix_visualize", "/nix/store/root"),
        ("parse_nix_visualize", graph_csv, True),
    ]
    assert artifact.cleaned
    assert not graph_csv.exists()
    assert data.repology.to_dict(orient="records") == _repology_df().to_dict(
        orient="records"
    )
    assert data.nix_visualize is not None
    assert data.nix_visualize.to_dict(orient="records") == [
        {
            "package": "hello",
            "version": "2.10",
            "level": "1",
        }
    ]


def test_collect_outdated_scan_data_buildtime_skips_nix_visualize(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(pipeline.LOG, "level", logging.INFO)
    artifact = FakeSbomArtifact(tmp_path / "deps.cdx.json")

    data = pipeline.collect_outdated_scan_data(
        "/nix/store/root.drv",
        buildtime=True,
        hooks=pipeline.OutdatedScanHooks(
            query_repology=lambda _sbom_path: _repology_df(),
            generate_temp_sbom=lambda *_args, **_kwargs: artifact,
            run_nix_visualize=lambda _target_path: (_ for _ in ()).throw(
                AssertionError("nix-visualize should not run for buildtime scans")
            ),
            parse_nix_visualize=lambda _csv_path: (_ for _ in ()).throw(
                AssertionError("nix-visualize output should not be parsed")
            ),
        ),
    )

    assert artifact.cleaned
    assert data.nix_visualize is None
    assert data.repology.to_dict(orient="records") == _repology_df().to_dict(
        orient="records"
    )


def test_generate_report_df_buildtime_adds_default_priority_and_renames_version():
    df_report = generate_report_df(None, _repology_df())

    assert list(df_report["level"]) == ["0"]
    assert list(df_report["version_repology"]) == ["2.11"]
    assert "version" not in df_report.columns


def test_write_report_defaults_to_nixpkgs_updates_and_drops_newest_duplicates(tmp_path):
    out_path = tmp_path / "nix_outdated.csv"
    df = pd.DataFrame(
        [
            {
                "level": "1",
                "package": "openssl",
                "version": "3.0",
                "version_sbom": "3.0",
                "version_repology": "3.1",
                "newest_upstream_release": "3.2",
                "status": "outdated",
                "repo_version_classify": "repo_pkg_needs_update",
                "sbom_version_classify": "",
            },
            {
                "level": "2",
                "package": "hello",
                "version": "2.10",
                "version_sbom": "2.10",
                "version_repology": "2.11",
                "newest_upstream_release": "2.12",
                "status": "outdated",
                "repo_version_classify": "repo_pkg_needs_update",
                "sbom_version_classify": "",
            },
            {
                "level": "3",
                "package": "hello",
                "version": "2.12",
                "version_sbom": "2.12",
                "version_repology": "2.12",
                "newest_upstream_release": "2.12",
                "status": "newest",
                "repo_version_classify": "",
                "sbom_version_classify": "",
            },
            {
                "level": "4",
                "package": "local-only",
                "version": "1.0",
                "version_sbom": "1.0",
                "version_repology": "1.1",
                "newest_upstream_release": "1.1",
                "status": "outdated",
                "repo_version_classify": "",
                "sbom_version_classify": "sbom_pkg_needs_update",
            },
        ]
    )

    write_report(
        df,
        SimpleNamespace(local=False, buildtime=False, out=out_path.as_posix()),
    )

    report = df_from_csv_file(out_path)
    assert report.to_dict(orient="records") == [
        {
            "priority": "1",
            "nix_package": "openssl",
            "version_local": "3.0",
            "version_nixpkgs": "3.1",
            "version_upstream": "3.2",
        }
    ]


def test_write_report_local_buildtime_outputs_local_updates_without_priority(tmp_path):
    out_path = tmp_path / "nix_outdated_local.csv"
    df = pd.DataFrame(
        [
            {
                "level": "0",
                "package": "local-only",
                "version": "1.0",
                "version_sbom": "1.0",
                "version_repology": "1.1",
                "newest_upstream_release": "1.2",
                "status": "outdated",
                "repo_version_classify": "",
                "sbom_version_classify": "sbom_pkg_needs_update",
            },
            {
                "level": "0",
                "package": "repo-only",
                "version": "2.0",
                "version_sbom": "2.0",
                "version_repology": "2.1",
                "newest_upstream_release": "2.2",
                "status": "outdated",
                "repo_version_classify": "repo_pkg_needs_update",
                "sbom_version_classify": "",
            },
        ]
    )

    write_report(
        df,
        SimpleNamespace(local=True, buildtime=True, out=out_path.as_posix()),
    )

    report = df_from_csv_file(out_path)
    assert list(report.columns) == [
        "nix_package",
        "version_local",
        "version_nixpkgs",
        "version_upstream",
    ]
    assert report.to_dict(orient="records") == [
        {
            "nix_package": "local-only",
            "version_local": "1.0",
            "version_nixpkgs": "1.1",
            "version_upstream": "1.2",
        }
    ]
