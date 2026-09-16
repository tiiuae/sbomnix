# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""HTML parser helpers for Repology project search pages."""

import re
from dataclasses import dataclass
from typing import NoReturn

from bs4 import BeautifulSoup

import repology.exceptions
from common import columns as cols
from common.log import LOG, LOG_SPAM

_EMPTY_PROJECTS_RESPONSES = {
    "no matches",
    "no projects found matching the criteria",
}


@dataclass
class ParsedProjectsPage:
    """Parsed data extracted from a Repology projects response."""

    package_rows: list[dict[str, str]]
    next_query_project: str
    processed_ids: set[str]


def _raise_unexpected_response(error=None) -> NoReturn:
    detail = "malformed Repology projects response"
    LOG.fatal("Unexpected response: %s", detail)
    raise repology.exceptions.RepologyUnexpectedResponse(detail) from error


def parse_projects_search_html(  # noqa: PLR0912, PLR0914, PLR0915
    html, repository, processed_ids=None, pkg_stop=None
):
    """Parse a Repology package search response."""
    processed_ids = set() if processed_ids is None else set(processed_ids)
    next_query_project = ""
    package_rows = []
    soup = BeautifulSoup(html, "html.parser")
    tables = soup.find_all("table")
    if not tables:
        if any(
            text.casefold() in _EMPTY_PROJECTS_RESPONSES
            for text in soup.stripped_strings
        ):
            LOG.debug("Projects table missing: no matching packages")
            return ParsedProjectsPage(package_rows, next_query_project, processed_ids)
        _raise_unexpected_response()

    projects_table = tables[0]
    if projects_table.thead is None or projects_table.tbody is None:
        _raise_unexpected_response()
    headers = {
        header.text: idx
        for idx, header in enumerate(projects_table.thead.find_all("th"))
    }
    required_headers = ("Newest", "Project", "Selected")
    try:
        required_cells = max(headers[name] for name in required_headers) + 1
    except KeyError as error:
        _raise_unexpected_response(error)
    table_rows = projects_table.tbody.find_all("tr")
    if not table_rows:
        _raise_unexpected_response()
    LOG.log(LOG_SPAM, headers)

    rows = 0
    stop_query = False
    for row in table_rows:
        cells = row.find_all("td")
        if not cells:
            continue
        if len(cells) < required_cells:
            _raise_unexpected_response()
        rows += 1
        LOG.log(LOG_SPAM, "cols: %s", cells)
        pkg_link = cells[headers["Project"]].find("a")
        if pkg_link is None:
            _raise_unexpected_response()
        pkg_name = pkg_link.get_text(strip=True)
        if not pkg_name:
            _raise_unexpected_response()
        if not stop_query and pkg_stop and pkg_name == pkg_stop:
            stop_query = True
            LOG.debug("Stopping queries after parsing the current response")
        pkg_id = f"{repository}:{pkg_name}"
        if pkg_id in processed_ids:
            LOG.debug("Package '%s' in search resp already processed", pkg_name)
            continue
        LOG.debug("Adding package '%s' to processed_ids", pkg_name)
        processed_ids.add(pkg_id)
        newest = cells[headers["Newest"]]
        newest_releases = [
            re.sub(r"[^\x00-\x7f]+", "", span.text)
            for span in newest.find_all("span", {"class": "version-newest"})
        ]
        selected = cells[headers["Selected"]]
        statuses = re.findall(r'version-([^"]+)"', str(selected))
        versions = selected.find_all("span", {"class": "version"})
        if not versions or len(statuses) != len(versions):
            _raise_unexpected_response()
        for status, version in zip(statuses, versions, strict=True):
            version_text = re.sub(r"[^\x00-\x7f]+", "", version.text).strip()
            if not version_text:
                _raise_unexpected_response()
            vulnerable = bool(version.find_all("span", {"class": "vulnerable"}))
            package_rows.append(
                {
                    cols.REPO: repository,
                    cols.PACKAGE: pkg_name,
                    cols.VERSION: version_text,
                    cols.STATUS: status,
                    cols.POTENTIALLY_VULNERABLE: str(int(vulnerable)),
                    cols.NEWEST_UPSTREAM_RELEASE: ";".join(newest_releases),
                }
            )
            LOG.log(LOG_SPAM, "Added: %s:%s:%s", pkg_name, version_text, status)
        if rows == 200 and not stop_query:
            next_query_project = pkg_name
    if not rows:
        _raise_unexpected_response()
    if rows > 200:
        LOG.warning(
            "Unexpected response: raising this warning to notify the "
            "possibility the repology API has changed and might no longer "
            "match what this client expects"
        )
    return ParsedProjectsPage(package_rows, next_query_project, processed_ids)
