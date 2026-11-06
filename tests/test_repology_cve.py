#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for Repology CVE queries."""

import pytest

from repology.cves import is_affected
from repology.exceptions import RepologyUnexpectedResponse
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


def test_query_cve_accepts_explicit_empty_page():
    url = "https://repology.org/project/openssl/cves?version=3.1.0"
    session = MappingSession(
        {
            url: FakeResponse(
                """
                <div class="alert alert-success" role="alert">
                  No CVEs known for this project. This is not reliable though
                  and may be caused by lacking CPE information or our simplified
                  CVE configurations parsing. Feel free to submit a report.
                </div>
                """
            )
        }
    )

    df = query_cve("openssl", "3.1.0", session=session)

    assert df.empty
    assert session.calls == [(url, REPOLOGY_REQUEST_TIMEOUT)]


def test_query_cve_rejects_malformed_html():
    url = "https://repology.org/project/openssl/cves?version=3.1.0"
    session = MappingSession(
        {url: FakeResponse("<html><body><h1>Maintenance</h1></body></html>")}
    )

    with pytest.raises(RepologyUnexpectedResponse):
        query_cve("openssl", "3.1.0", session=session)

    assert session.calls == [(url, REPOLOGY_REQUEST_TIMEOUT)]


@pytest.mark.parametrize(
    ("version", "affected", "expected"),
    [
        ("0.9.8a", "(-∞, 0.9.8g]", True),
        ("0.9.8g", "(-∞, 0.9.8g]", True),
        ("3.1.0", "(-∞, 0.9.8g]", False),
        ("1.0.2", "(-∞, 1.0.2)", False),
        ("2.0", "[1.0, +∞)", True),
        ("0.5", "[1.0, +∞)", False),
    ],
)
def test_is_affected_handles_open_ended_ranges(version, affected, expected):
    assert is_affected(version, affected) is expected


@pytest.mark.parametrize(
    ("version", "affected", "expected"),
    [
        ("0.9.8a", "(-∞, 0.9.8zh)", True),
        ("0.9.8zh", "(-∞, 0.9.8zh)", False),
        ("0.9.8z", "(-∞, 0.9.8zh)", True),
        ("0.9.8", "(-∞, 0.9.8a]", True),
        ("0.9.8b", "(-∞, 0.9.8a]", False),
        ("1.0.1h", "[1.0.1, 1.0.1g]", False),
        ("1.0.1", "(1.0.1, 1.0.1g]", False),
        ("1.0.1c", "(1.0.1, 1.0.1g]", True),
        ("1.0.1g", "1.0.1g", True),
        ("1.0.1h", "1.0.1g", False),
    ],
)
def test_is_affected_compares_letter_suffixes(version, affected, expected):
    assert is_affected(version, affected) is expected


@pytest.mark.parametrize(
    ("version", "affected"),
    [
        ("3.0.0-rc1", "(-∞, 1.0.2)"),
        ("3.0.0beta1", "(-∞, 1.0.2)"),
        ("1.0.2", "(-∞, 3.0.0-alpha1]"),
        ("2024-01-15", "(-∞, 1.0.2)"),
        ("1.0.2", "[foo, bar)"),
    ],
)
def test_is_affected_assumes_affected_when_not_comparable(version, affected):
    assert is_affected(version, affected) is True


def test_query_cve_keeps_letter_suffix_cves():
    url = "https://repology.org/project/openssl/cves?version=0.9.8a"
    html = """
    <table>
      <thead><tr><th>CVE ID</th><th>Affected version(s)</th></tr></thead>
      <tbody>
        <tr>
          <td>CVE-2015-3195</td>
          <td><span class="version version-outdated">(-∞, 0.9.8zh)</span></td>
        </tr>
        <tr>
          <td>CVE-2016-2105</td>
          <td><span class="version version-outdated">[1.0.1, 1.0.1t)</span></td>
        </tr>
      </tbody>
    </table>
    """
    session = MappingSession({url: FakeResponse(html)})

    df = query_cve("openssl", "0.9.8a", session=session)

    assert list(df["cve"]) == ["CVE-2015-3195"]
