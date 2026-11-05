#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for vulnxscan triage and lookup helpers."""

from types import SimpleNamespace
from unittest.mock import Mock

import pandas as pd
import pytest
from requests import HTTPError

from common import columns as cols
from vulnxscan.github_prs import GitHubPrLookup, GitHubUnexpectedResponse
from vulnxscan.repology_lookup import RepologyVulnerabilityLookup
from vulnxscan.triage import triage_vulnerabilities


class FakeRepologyLookup:
    def __init__(self):
        self.query_inputs = []

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
    def find_nixpkgs_prs(self, row):
        return "https://github.com/NixOS/nixpkgs/pull/1"


class TwoRowRepologyLookup(FakeRepologyLookup):
    def query_repology_versions(self, df_vuln_pkgs):
        self.query_inputs.append(df_vuln_pkgs.copy(deep=True))
        return pd.DataFrame(
            [
                {
                    "vuln_id": f"CVE-2024-{index}",
                    "url": f"https://nvd.nist.gov/vuln/detail/CVE-2024-{index}",
                    "package": "openssl",
                    "severity": "7.0",
                    "version_local": "1.0.0",
                    "version_nixpkgs": "1.1.0",
                    "version_upstream": "1.2.0",
                    "package_repology": "openssl",
                    "sortcol": f"2024A000000000{index}",
                }
                for index in (1, 2)
            ]
        )


class FailingGitHubLookup:
    def __init__(self, error, fail_after=0):
        self.error = error
        self.fail_after = fail_after
        self.calls = 0

    def find_nixpkgs_prs(self, row):
        self.calls += 1
        if self.calls > self.fail_after:
            raise self.error
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
    assert triaged["nixpkgs_pr"].tolist() == ["https://github.com/NixOS/nixpkgs/pull/1"]


def test_github_pr_lookup_queries_vuln_id_and_skips_whitelisted_rows():
    lookup = GitHubPrLookup(session=SimpleNamespace())
    pr_url = "https://github.com/NixOS/nixpkgs/pull"
    lookup.query = Mock(
        side_effect=[
            {"items": [{"html_url": f"{pr_url}/{number}"} for number in numbers]}
            for numbers in ((3, 2), (2, 1))
        ]
    )
    row = SimpleNamespace(
        vuln_id="CVE-2024-1",
        package="openssl",
        version_nixpkgs="1.1.0",
        version_upstream="1.2.0",
        classify="",
        whitelist=False,
    )

    assert lookup.find_nixpkgs_prs(row) == f"{pr_url}/1 \n{pr_url}/2 \n{pr_url}/3"
    assert [call.args[0] for call in lookup.query.call_args_list] == [
        "repo:NixOS/nixpkgs is:pr is:unmerged is:open CVE-2024-1",
        "repo:NixOS/nixpkgs is:pr is:merged CVE-2024-1",
    ]
    row.whitelist = True
    assert lookup.find_nixpkgs_prs(row) == ""
    assert lookup.query.call_count == 2


@pytest.mark.parametrize(
    ("github_error", "fail_after"),
    [
        (HTTPError("503 Server Error: Service Unavailable"), 0),
        (GitHubUnexpectedResponse("malformed GitHub search response"), 1),
    ],
    ids=["request-error", "unexpected-response"],
)
def test_triage_vulnerabilities_keeps_repology_result_when_github_fails(
    fail_after, github_error, caplog
):
    """Retain the Repology version hints when GitHub enrichment fails."""
    repology_lookup = TwoRowRepologyLookup()
    github_lookup = FailingGitHubLookup(github_error, fail_after=fail_after)
    df_report = pd.DataFrame(
        [
            {
                "vuln_id": "CVE-2024-1",
                "package": "openssl",
                "severity": "7.0",
                "version": "1.0.0",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
                "sortcol": "2024A0000000001",
            }
        ]
    )

    triaged = triage_vulnerabilities(
        df_report,
        True,
        repology_lookup=repology_lookup,
        github_lookup=github_lookup,
    )

    assert triaged["classify"].tolist() == [""] * 2
    assert triaged["version_nixpkgs"].tolist() == ["1.1.0"] * 2
    assert triaged["version_upstream"].tolist() == ["1.2.0"] * 2
    assert triaged[cols.NIXPKGS_PR].tolist() == ["", ""]
    assert github_lookup.calls == fail_after + 1
    assert str(github_error) in caplog.text


@pytest.mark.parametrize(
    "response_text",
    [
        "<html>",
        '{"items": [null]}',
    ],
    ids=["invalid-json", "invalid-structure"],
)
def test_github_pr_lookup_rejects_malformed_response(response_text):
    response = SimpleNamespace(
        ok=True,
        text=response_text,
        raise_for_status=lambda: None,
    )
    session = SimpleNamespace(get=lambda *_args, **_kwargs: response)
    lookup = GitHubPrLookup(session=session)

    with pytest.raises(GitHubUnexpectedResponse, match="malformed GitHub"):
        lookup.query("CVE-2024-1")


def test_query_repology_versions_prefers_exact_version_match():
    adapter = FakeAdapter()
    lookup = RepologyVulnerabilityLookup(adapter=adapter)
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


def test_query_repology_versions_preserves_evidence_columns_without_match():
    class EmptyAdapter:
        def query(self, _repology_query):
            return None

    lookup = RepologyVulnerabilityLookup(adapter=EmptyAdapter())
    df_vuln_pkgs = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-2024-1",
                cols.URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
                cols.PACKAGE: "openssl",
                cols.SEVERITY: "7.0",
                cols.VERSION: "1.0.0",
                cols.SORTCOL: "2024A0000000001",
                cols.FINDING_ID: "sha256:test",
                cols.EVIDENCE_SCOPE: "component_expanded",
                cols.PATCH_STATE: "mixed_component_evidence",
                cols.RESOLVED_COMPONENT_COUNT: 2,
                cols.VULN_ID_PATCH_NAME_MATCH_COUNT: 1,
                cols.NO_VULN_ID_PATCH_NAME_MATCH_COUNT: 1,
                cols.METADATA_UNAVAILABLE_COUNT: 0,
                cols.PACKAGE_VERSION_ONLY_COUNT: 0,
            }
        ]
    )

    result = lookup.query_repology_versions(df_vuln_pkgs)

    assert result[cols.FINDING_ID].tolist() == ["sha256:test"]
    assert result[cols.PATCH_STATE].tolist() == ["mixed_component_evidence"]
    assert result[cols.RESOLVED_COMPONENT_COUNT].tolist() == [2]


def test_query_repology_versions_repeats_evidence_on_every_candidate_row():
    """One finding may expand into several rows; each repeats its evidence."""

    class TwoCandidateAdapter:
        def query(self, _repology_query):
            return pd.DataFrame(
                [
                    {
                        "package": "openssl",
                        "version": "1.1.0",
                        "status": "newest",
                        "newest_upstream_release": "1.2.0",
                    },
                    {
                        "package": "openssl-legacy",
                        "version": "1.1.0",
                        "status": "newest",
                        "newest_upstream_release": "1.1.9",
                    },
                ]
            )

    lookup = RepologyVulnerabilityLookup(adapter=TwoCandidateAdapter())
    df_vuln_pkgs = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-2024-1",
                cols.URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
                cols.PACKAGE: "openssl",
                cols.SEVERITY: "7.0",
                cols.VERSION: "1.0.0",
                cols.SORTCOL: "2024A0000000001",
                cols.FINDING_ID: "sha256:test",
                cols.EVIDENCE_SCOPE: "component_expanded",
                cols.PATCH_STATE: "mixed_component_evidence",
                cols.RESOLVED_COMPONENT_COUNT: 2,
                cols.VULN_ID_PATCH_NAME_MATCH_COUNT: 1,
                cols.NO_VULN_ID_PATCH_NAME_MATCH_COUNT: 1,
                cols.METADATA_UNAVAILABLE_COUNT: 0,
                cols.PACKAGE_VERSION_ONLY_COUNT: 0,
            }
        ]
    )

    result = lookup.query_repology_versions(df_vuln_pkgs)

    assert len(result) == 2
    assert result[cols.PACKAGE_REPOLOGY].tolist() == ["openssl", "openssl-legacy"]
    assert result[cols.FINDING_ID].tolist() == ["sha256:test"] * 2
    assert result[cols.PATCH_STATE].tolist() == ["mixed_component_evidence"] * 2
    assert result[cols.RESOLVED_COMPONENT_COUNT].tolist() == [2, 2]
    assert result[cols.VULN_ID_PATCH_NAME_MATCH_COUNT].tolist() == [1, 1]


def test_query_repology_rejects_unknown_match_type():
    lookup = RepologyVulnerabilityLookup(adapter=FakeAdapter())

    with pytest.raises(ValueError, match="Unknown match_type: 'bad'"):
        lookup.query_repology("openssl", match_type="bad")
