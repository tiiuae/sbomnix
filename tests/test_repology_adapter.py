#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-class-docstring,missing-function-docstring
# pylint: disable=too-few-public-methods

"""Offline tests for the Repology adapter."""

import json

import pytest

from repology.adapter import RepologyAdapter, RepologyQuery
from repology.exceptions import RepologyNoMatchingPackages
from repology.session import REPOLOGY_REQUEST_TIMEOUT
from tests.testpaths import RESOURCES_DIR

REPOLOGY_FIXTURES_DIR = RESOURCES_DIR / "repology"


class FakeResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"unexpected status code: {self.status_code}")


class MappingSession:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append((url, timeout))
        if url not in self.responses:
            raise AssertionError(f"unexpected URL requested: {url}")
        return self.responses[url]


def _fixture_text(name):
    return (REPOLOGY_FIXTURES_DIR / name).read_text(encoding="utf-8")


def test_repology_adapter_pkg_exact_parses_fixture_and_uses_timeout():
    url = "https://repology.org/projects/?search=hello&inrepo=nix_unstable"
    session = MappingSession(
        {
            url: FakeResponse(_fixture_text("projects_hello.html")),
        }
    )

    df = RepologyAdapter(session=session).query(
        RepologyQuery(
            repository="nix_unstable",
            pkg_exact="hello",
        )
    )

    assert session.calls == [(url, REPOLOGY_REQUEST_TIMEOUT)]
    assert list(df["package"].unique()) == ["hello"]
    assert set(df["status"]) == {"newest", "outdated"}
    outdated = df[df["status"] == "outdated"].iloc[0]
    assert outdated["version"] == "2.10"
    assert outdated["potentially_vulnerable"] == "1"
    assert outdated["newest_upstream_release"] == "2.11;2.12-rc1"
    assert outdated["repo_version_classify"] == "repo_pkg_needs_update"


def test_repology_adapter_pkg_exact_raises_for_empty_results():
    url = "https://repology.org/projects/?search=missing&inrepo=nix_unstable"
    session = MappingSession(
        {
            url: FakeResponse(_fixture_text("projects_empty.html")),
        }
    )

    with pytest.raises(RepologyNoMatchingPackages):
        RepologyAdapter(session=session).query(
            RepologyQuery(
                repository="nix_unstable",
                pkg_exact="missing",
            )
        )

    assert session.calls == [(url, REPOLOGY_REQUEST_TIMEOUT)]


def test_repology_adapter_sbom_query_marks_special_statuses(tmp_path):
    sbom_path = tmp_path / "sbom.cdx.json"
    sbom_path.write_text(
        json.dumps(
            {
                "metadata": {},
                "components": [
                    {"name": "hello", "version": "2.10"},
                    {"name": "archive.tar.gz", "version": "1.0"},
                    {"name": "missingver", "version": ""},
                    {"name": "missingpkg", "version": "9.9"},
                ],
            }
        ),
        encoding="utf-8",
    )
    hello_url = "https://repology.org/projects/?search=hello&inrepo=nix_unstable"
    missing_url = "https://repology.org/projects/?search=missingpkg&inrepo=nix_unstable"
    session = MappingSession(
        {
            hello_url: FakeResponse(_fixture_text("projects_hello.html")),
            missing_url: FakeResponse(_fixture_text("projects_empty.html")),
        }
    )

    df = RepologyAdapter(session=session).query(
        RepologyQuery(
            repository="nix_unstable",
            sbom_cdx=sbom_path,
        )
    )

    assert session.calls == [
        (hello_url, REPOLOGY_REQUEST_TIMEOUT),
        (missing_url, REPOLOGY_REQUEST_TIMEOUT),
    ]
    assert set(df["status"]) == {
        "IGNORED",
        "NOT_FOUND",
        "NO_VERSION",
        "newest",
        "outdated",
    }
    hello_rows = df[df["package"] == "hello"]
    assert set(hello_rows["sbom_version_classify"]) == {"sbom_pkg_needs_update"}
    assert set(hello_rows["repo_version_classify"]) == {
        "",
        "repo_pkg_needs_update",
    }
    assert df[df["package"] == "archive.tar.gz"].iloc[0]["status"] == "IGNORED"
    assert df[df["package"] == "missingver"].iloc[0]["status"] == "NO_VERSION"
    assert df[df["package"] == "missingpkg"].iloc[0]["status"] == "NOT_FOUND"
