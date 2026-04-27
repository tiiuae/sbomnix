#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-class-docstring,missing-function-docstring,too-few-public-methods

"""Unit tests for vulnxscan triage and lookup helpers."""

from types import SimpleNamespace

import pandas as pd

from vulnxscan.github_prs import GitHubPrLookup
from vulnxscan.repology_lookup import RepologyVulnerabilityLookup
from vulnxscan.triage import classify_vulnerability, triage_vulnerabilities


class FakeRepologyLookup:
    def __init__(self):
        self.vulnerable_checks = []
        self.query_inputs = []

    def is_vulnerable(self, package, version, vuln_id=None):
        self.vulnerable_checks.append((package, str(version), vuln_id))
        return str(version) == "1.0.0"

    def query_repology_versions(self, df_vuln_pkgs):
        self.query_inputs.append(df_vuln_pkgs.copy(deep=True))
        return pd.DataFrame(
            [
                {
                    "vuln_id": "CVE-2024-1",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
                    "package": "openssl",
                    "severity": "7.0",
                    "version_local": "1.0.0",
                    "version_nixpkgs": "1.1.0",
                    "version_upstream": "1.2.0",
                    "package_repology": "openssl",
                    "sortcol": "2024A0000000001",
                }
            ]
        )


class FakeGitHubLookup:
    def __init__(self):
        self.rows = []

    def find_nixpkgs_prs(self, row):
        self.rows.append(row)
        return "https://github.com/NixOS/nixpkgs/pull/1"


class FakeAdapter:
    def __init__(self):
        self.queries = []

    def query(self, repology_query):
        self.queries.append(repology_query)
        return pd.DataFrame(
            [
                {
                    "package": "tiff",
                    "version": "4.5.0",
                    "status": "newest",
                    "newest_upstream_release": "4.5.1",
                },
                {
                    "package": "tiff-tools",
                    "version": "4.4.0",
                    "status": "newest",
                    "newest_upstream_release": "4.4.2",
                },
            ]
        )


def test_classify_vulnerability_marks_fixable_nixpkgs_update():
    lookup = FakeRepologyLookup()
    row = SimpleNamespace(
        vuln_id="CVE-2024-1",
        package_repology="openssl",
        version_local="1.0.0",
        version_nixpkgs="1.1.0",
        version_upstream="1.2.0",
    )

    classification = classify_vulnerability(row, repology_lookup=lookup)

    assert classification == "fix_update_to_version_nixpkgs"
    assert lookup.vulnerable_checks == [
        ("openssl", "1.0.0", "CVE-2024-1"),
        ("openssl", "1.1.0", "CVE-2024-1"),
    ]


def test_triage_vulnerabilities_groups_rows_and_adds_nixpkgs_prs():
    repology_lookup = FakeRepologyLookup()
    github_lookup = FakeGitHubLookup()
    df_report = pd.DataFrame(
        [
            {
                "vuln_id": "CVE-2024-1",
                "package": "openssl",
                "severity": "7.0",
                "version": "1.0.0",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
                "sortcol": "2024A0000000001",
            },
            {
                "vuln_id": "CVE-2024-1",
                "package": "openssl",
                "severity": "7.0",
                "version": "1.0.0",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
                "sortcol": "2024A0000000001",
            },
        ]
    )

    triaged = triage_vulnerabilities(
        df_report,
        True,
        repology_lookup=repology_lookup,
        github_lookup=github_lookup,
    )

    assert repology_lookup.query_inputs[0]["count"].tolist() == [2]
    assert triaged["classify"].tolist() == ["fix_update_to_version_nixpkgs"]
    assert triaged["nixpkgs_pr"].tolist() == ["https://github.com/NixOS/nixpkgs/pull/1"]


def test_github_pr_lookup_queries_vuln_and_version_matches():
    queries = []
    lookup = GitHubPrLookup(
        session=SimpleNamespace(get=None), sleeper=lambda _delay: None
    )

    def fake_query(query_str, delay=60):
        queries.append((query_str, delay))
        return {
            "total_count": 1,
            "items": [
                {"html_url": f"https://github.com/NixOS/nixpkgs/pull/{len(queries)}"}
            ],
        }

    lookup.query = fake_query
    row = SimpleNamespace(
        vuln_id="CVE-2024-1",
        classify="fix_update_to_version_nixpkgs",
        version_nixpkgs="1.2.3",
        version_upstream="",
        package="openssl",
        whitelist=False,
    )

    prs = lookup.find_nixpkgs_prs(row)

    assert queries == [
        ("repo:NixOS/nixpkgs is:pr is:unmerged is:open CVE-2024-1", 60),
        ("repo:NixOS/nixpkgs is:pr is:merged CVE-2024-1", 60),
        (
            "repo:NixOS/nixpkgs is:pr is:unmerged is:open openssl in:title 1.2.3 in:title",
            60,
        ),
        ("repo:NixOS/nixpkgs is:pr is:merged openssl in:title 1.2.3 in:title", 60),
    ]
    assert prs == (
        "https://github.com/NixOS/nixpkgs/pull/1 \n"
        "https://github.com/NixOS/nixpkgs/pull/2 \n"
        "https://github.com/NixOS/nixpkgs/pull/3 \n"
        "https://github.com/NixOS/nixpkgs/pull/4"
    )


def test_query_repology_versions_prefers_exact_version_match():
    adapter = FakeAdapter()
    lookup = RepologyVulnerabilityLookup(adapter=adapter, cve_query=lambda *_args: None)
    df_vuln_pkgs = pd.DataFrame(
        [
            {
                "vuln_id": "CVE-2024-2",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-2",
                "package": "libtiff",
                "severity": "5.0",
                "version": "4.5.0",
                "sortcol": "2024A0000000002",
                "count": 1,
            }
        ]
    )

    result = lookup.query_repology_versions(df_vuln_pkgs)

    assert len(adapter.queries) == 1
    assert result.to_dict("records") == [
        {
            "vuln_id": "CVE-2024-2",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-2",
            "package": "libtiff",
            "severity": "5.0",
            "version_local": "4.5.0",
            "version_nixpkgs": "4.5.0",
            "version_upstream": "4.5.1",
            "package_repology": "tiff",
            "sortcol": "2024A0000000002",
        }
    ]
