#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""GitHub PR search helpers for vulnerability triage."""

import json
import time
import urllib.parse

from common.http import create_cached_limited_session
from common.log import LOG, LOG_SPAM

GITHUB_API_CACHE_SECONDS = 6 * 60 * 60
GITHUB_API_REQUEST_TIMEOUT = 60
GITHUB_API_USER_AGENT = "sbomnix-github-prs/0 (https://github.com/tiiuae/sbomnix/)"


def append_search_results(prs, result, max_results=5):
    """Append GitHub issue search result URLs to ``result``."""
    for item in prs["items"]:
        if len(result) >= max_results:
            LOG.log(
                LOG_SPAM,
                "More than %s PRs, skipping: %s",
                max_results,
                item["html_url"],
            )
            continue
        result.add(item["html_url"])
    return result


class GitHubPrLookup:
    """Search likely nixpkgs PRs related to a vulnerability."""

    def __init__(
        self,
        session=None,
        sleeper=None,
        request_timeout=GITHUB_API_REQUEST_TIMEOUT,
    ):
        self.session = (
            create_cached_limited_session(
                per_minute=9,
                per_second=1,
                expire_after=GITHUB_API_CACHE_SECONDS,
                user_agent=GITHUB_API_USER_AGENT,
            )
            if session is None
            else session
        )
        self.sleeper = time.sleep if sleeper is None else sleeper
        self.request_timeout = request_timeout

    def query(self, query_str, delay=60):
        """Query the GitHub issues search API."""
        query_str_quoted = urllib.parse.quote(query_str, safe=":/")
        query = f"https://api.github.com/search/issues?q={query_str_quoted}"
        LOG.debug("GET: %s", query)
        resp = self.session.get(query, timeout=self.request_timeout)
        if not resp.ok and "rate limit exceeded" in resp.text:
            max_delay = 60
            if delay > max_delay:
                LOG.warning("Rate limit exceeded requesting %s", query)
                return {"items": []}
            LOG.debug("Sleeping %s seconds before re-requesting", delay)
            self.sleeper(delay)
            LOG.debug("Re-requesting")
            return self.query(query_str, delay * 2)
        resp.raise_for_status()
        resp_json = json.loads(resp.text)
        LOG.log(LOG_SPAM, "total_count=%s", resp_json["total_count"])
        return resp_json

    def find_nixpkgs_prs(self, row):
        """Return likely nixpkgs PR URLs for a vulnerable package row."""
        if hasattr(row, "whitelist") and row.whitelist:
            LOG.log(LOG_SPAM, "Whitelisted, skipping PR query: %s", row)
            return ""
        nixpr = "repo:NixOS/nixpkgs is:pr"
        unmerged = "is:unmerged is:open"
        merged = "is:merged"
        version = None
        result = set()
        append_search_results(self.query(f"{nixpr} {unmerged} {row.vuln_id}"), result)
        append_search_results(self.query(f"{nixpr} {merged} {row.vuln_id}"), result)
        if row.classify == "fix_update_to_version_nixpkgs":
            version = row.version_nixpkgs
        elif row.classify == "fix_update_to_version_upstream":
            version = row.version_upstream
        if version:
            pkg = row.package
            append_search_results(
                self.query(f"{nixpr} {unmerged} {pkg} in:title {version} in:title"),
                result,
            )
            append_search_results(
                self.query(f"{nixpr} {merged} {pkg} in:title {version} in:title"),
                result,
            )
        return " \n".join(sorted(result))
