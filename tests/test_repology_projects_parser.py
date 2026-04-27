#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-function-docstring

"""Offline tests for the Repology projects-page parser."""

import pytest

from repology.exceptions import RepologyUnexpectedResponse
from repology.projects_parser import parse_projects_search_html
from tests.testpaths import RESOURCES_DIR

REPOLOGY_FIXTURES_DIR = RESOURCES_DIR / "repology"


def _fixture_text(name):
    return (REPOLOGY_FIXTURES_DIR / name).read_text(encoding="utf-8")


def test_parse_projects_search_html_parses_fixture_rows():
    parsed = parse_projects_search_html(
        _fixture_text("projects_hello.html"),
        "nix_unstable",
    )

    assert parsed.next_query_project == ""
    assert parsed.processed_ids == {"nix_unstable:hello"}
    assert parsed.package_rows == [
        {
            "repo": "nix_unstable",
            "package": "hello",
            "version": "2.10",
            "status": "outdated",
            "potentially_vulnerable": "1",
            "newest_upstream_release": "2.11;2.12-rc1",
        },
        {
            "repo": "nix_unstable",
            "package": "hello",
            "version": "2.11",
            "status": "newest",
            "potentially_vulnerable": "0",
            "newest_upstream_release": "2.11;2.12-rc1",
        },
    ]


def test_parse_projects_search_html_respects_already_processed_packages():
    parsed = parse_projects_search_html(
        _fixture_text("projects_hello.html"),
        "nix_unstable",
        processed_ids={"nix_unstable:hello"},
    )

    assert parsed.next_query_project == ""
    assert parsed.processed_ids == {"nix_unstable:hello"}
    assert not parsed.package_rows


def test_parse_projects_search_html_raises_for_malformed_table():
    malformed = """
    <html>
      <body>
        <table>
          <thead><tr><th>Project</th></tr></thead>
        </table>
      </body>
    </html>
    """

    with pytest.raises(RepologyUnexpectedResponse):
        parse_projects_search_html(malformed, "nix_unstable")
