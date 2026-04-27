#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-class-docstring,missing-function-docstring
# pylint: disable=too-few-public-methods

"""Offline tests for Repology CVE queries."""

from repology.repology_cve import query_cve
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


def test_query_cve_parses_fixture_and_uses_timeout():
    url = "https://repology.org/project/openssl/cves?version=3.1.0"
    session = MappingSession(
        {
            url: FakeResponse(
                (REPOLOGY_FIXTURES_DIR / "cves_openssl.html").read_text(
                    encoding="utf-8"
                )
            ),
        }
    )

    df = query_cve("openssl", "3.1.0", session=session)

    assert session.calls == [(url, REPOLOGY_REQUEST_TIMEOUT)]
    assert list(df["package"]) == ["openssl"]
    assert list(df["version"]) == ["3.1.0"]
    assert list(df["cve"]) == ["CVE-2024-1111"]
