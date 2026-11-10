#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Offline checks for nixpkgs PR search outcomes and caching."""

import json
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import unquote

import pytest
from requests import HTTPError, Response
from requests.adapters import HTTPAdapter
from urllib3.response import HTTPResponse

from vulnxscan.github_prs import GitHubPrLookup

PR_URL = "https://github.com/NixOS/nixpkgs/pull"


def _response(*numbers, incomplete=False, status=200, text=None):
    response = Response()
    response.status_code = status
    response._content = (
        text
        if text is not None
        else json.dumps(
            {
                "items": [{"html_url": f"{PR_URL}/{number}"} for number in numbers],
                "incomplete_results": incomplete,
            }
        )
    ).encode()
    response.raw = HTTPResponse(body=response.content, preload_content=False)
    return response


def test_lookup_reuses_queries_limits_links_and_skips_whitelisted_findings():
    session = Mock()
    session.get.side_effect = [
        _response(1, 2, 3, 4),
        _response(3, 4, 5, 6),
        _response(),
        _response(),
    ]
    lookup = GitHubPrLookup(session=session)
    row = SimpleNamespace(vuln_id="CVE-2024-1", package="openssl", whitelist=False)
    expected = " \n".join(f"{PR_URL}/{number}" for number in range(1, 6)), "ok"

    assert lookup.find_nixpkgs_prs(row) == expected
    row.package = "another-package"
    assert lookup.find_nixpkgs_prs(row) == expected
    row.whitelist = True
    assert lookup.find_nixpkgs_prs(row) == ("", "skipped")
    assert session.get.call_count == 2
    assert [
        unquote(call.args[0]).split("?q=")[1] for call in session.get.call_args_list
    ] == [
        "repo:NixOS/nixpkgs is:pr is:unmerged is:open CVE-2024-1",
        "repo:NixOS/nixpkgs is:pr is:merged CVE-2024-1",
    ]
    row.whitelist = False
    row.vuln_id = "GHSA-abcd-1234-5678"
    assert lookup.find_nixpkgs_prs(row) == ("", "ok")
    assert session.get.call_count == 4


@pytest.mark.parametrize("failure", ["http", "malformed", "incomplete", "rate-limit"])
def test_lookup_keeps_partial_links_and_stops_after_failures(failure, caplog):
    caplog.set_level("WARNING")
    failures = {
        "http": [HTTPError("service unavailable")],
        "malformed": [_response(text='{"items": [null]}')],
        "incomplete": [_response(2, incomplete=True)],
        "rate-limit": [_response(status=403, text="rate limit exceeded")] * 2,
    }
    session = Mock()
    session.get.side_effect = [
        _response(1),
        *failures[failure],
        _response(3),
        _response(),
    ]
    sleeper = Mock()
    lookup = GitHubPrLookup(session=session, sleeper=sleeper)
    row = SimpleNamespace(vuln_id="CVE-2024-1")
    urls = f"{PR_URL}/1 \n{PR_URL}/2" if failure == "incomplete" else f"{PR_URL}/1"

    assert lookup.find_nixpkgs_prs(row) == (urls, "unavailable")
    assert lookup.find_nixpkgs_prs(row) == (urls, "unavailable")
    assert session.get.call_count == 1 + len(failures[failure])
    assert len(caplog.records) == 1
    if failure == "rate-limit":
        sleeper.assert_called_once_with(60)
    else:
        sleeper.assert_not_called()
    stopped = failure != "incomplete"
    assert lookup.find_nixpkgs_prs(SimpleNamespace(vuln_id="CVE-2024-2")) == (
        ("", "unavailable") if stopped else (f"{PR_URL}/3", "ok")
    )
    assert session.get.call_count == 1 + len(failures[failure]) + (0 if stopped else 2)
    assert len(caplog.records) == 1


@pytest.mark.parametrize(
    "text",
    ['{"items": [], "incomplete_results": true}', "<html>", '{"items": []}'],
    ids=["incomplete", "invalid-json", "missing-completeness"],
)
def test_incomplete_and_malformed_responses_are_not_persisted(
    tmp_path, monkeypatch, text
):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    responses = iter([_response(text=text), _response(), _response(1)])
    sent = []

    def send(_adapter, request, **_kwargs):
        sent.append(request.url)
        response = next(responses)
        response.request = request
        response.url = request.url
        return response

    monkeypatch.setattr(HTTPAdapter, "send", send)
    row = SimpleNamespace(vuln_id="CVE-2024-1")
    for expected in [("", "unavailable"), (f"{PR_URL}/1", "ok"), (f"{PR_URL}/1", "ok")]:
        lookup = GitHubPrLookup()
        try:
            assert lookup.find_nixpkgs_prs(row) == expected
        finally:
            lookup.session.close()
    assert len(sent) == 3
