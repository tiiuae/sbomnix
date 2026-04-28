#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for the reusable OSV client."""

from vulnxscan.osv_client import OSV


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class FakeSession:
    def __init__(self):
        self.calls = []

    def post(self, url, json=None, timeout=None):
        self.calls.append((url, json, timeout))
        return FakeResponse(
            {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "OSV-1",
                                "modified": "2024-01-01",
                            }
                        ]
                    }
                ]
            }
        )


def test_osv_client_posts_with_timeout_and_parses_results(tmp_path):
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(
        ('{"metadata":{"component":{"name":"hello","version":"1.0"}},"components":[]}'),
        encoding="utf-8",
    )

    session = FakeSession()
    osv = OSV(session=session, request_timeout=17)

    osv.query_vulns(sbom_path.as_posix(), ecosystems=["GIT"])

    assert session.calls == [
        (
            "https://api.osv.dev/v1/querybatch",
            {
                "queries": [
                    {
                        "version": "1.0",
                        "package": {
                            "name": "hello",
                            "ecosystem": "GIT",
                        },
                    }
                ]
            },
            17,
        )
    ]
    assert osv.to_dataframe().to_dict(orient="records") == [
        {
            "vuln_id": "OSV-1",
            "modified": "2024-01-01",
            "package": "hello",
            "version": "1.0",
        }
    ]
