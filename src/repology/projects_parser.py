# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-branches,too-many-locals,too-many-statements

"""HTML parser helpers for Repology project search pages."""

import re
from dataclasses import dataclass

from bs4 import BeautifulSoup

import repology.exceptions
from common import columns as cols
from common.log import LOG, LOG_SPAM


@dataclass
class ParsedProjectsPage:
    """Parsed data extracted from a Repology projects response."""

    package_rows: list[dict[str, str]]
    next_query_project: str
    processed_ids: set[str]


def parse_projects_search_html(html, repository, processed_ids=None, pkg_stop=None):
    """Parse a Repology package search response."""
    processed_ids = set() if processed_ids is None else set(processed_ids)
    next_query_project = ""
    package_rows = []
    soup = BeautifulSoup(html, "html.parser")
    tables = soup.find_all("table")
    if not tables:
        LOG.debug("Projects table missing: no matching packages")
        return ParsedProjectsPage(package_rows, next_query_project, processed_ids)
    projects_table = tables[0]
    if projects_table.thead is None or projects_table.tbody is None:
        LOG.fatal("Unexpected response, malformed projects table")
        raise repology.exceptions.RepologyUnexpectedResponse
    headers = {}
    for idx, header in enumerate(projects_table.thead.find_all("th")):
        headers[header.text] = idx
    if not headers:
        LOG.fatal("Unexpected response, missing headers")
        raise repology.exceptions.RepologyUnexpectedResponse
    LOG.log(LOG_SPAM, headers)
    rows = 0
    stop_query = False
    for row in projects_table.tbody.find_all("tr"):
        cells = row.find_all("td")
        if not cells:
            LOG.log(LOG_SPAM, "No columns on row: %s", row)
            continue
        rows += 1
        LOG.log(LOG_SPAM, "cols: %s", cells)
        pkg = cells[headers["Project"]]
        pkg_links = pkg.find_all("a")
        if not pkg_links:
            LOG.fatal("Unexpected response, missing project link")
            raise repology.exceptions.RepologyUnexpectedResponse
        pkg_name = pkg_links[0].string
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
        newest_releases = []
        for nspan in newest.find_all("span", {"class": "version-newest"}):
            rel_version = re.sub(r"[^\x00-\x7f]+", "", nspan.text)
            newest_releases.append(rel_version)
        sel = cells[headers["Selected"]]
        statuses = re.findall(r'version-([^"]+)"', str(sel))
        vspans = sel.find_all("span", {"class": "version"})
        for idx, vspan in enumerate(vspans):
            ver = re.sub(r"[^\x00-\x7f]+", "", vspan.text)
            vulnerable = bool(vspan.find_all("span", {"class": "vulnerable"}))
            status = statuses[idx]
            package_rows.append(
                {
                    cols.REPO: repository,
                    cols.PACKAGE: pkg_name,
                    cols.VERSION: ver,
                    cols.STATUS: status,
                    cols.POTENTIALLY_VULNERABLE: str(int(vulnerable)),
                    cols.NEWEST_UPSTREAM_RELEASE: ";".join(newest_releases),
                }
            )
            LOG.log(LOG_SPAM, "Added: %s:%s:%s", pkg_name, ver, status)
        if rows == 200 and not stop_query:
            next_query_project = pkg_name
    if rows > 200:
        LOG.warning(
            "Unexpected response: raising this warning to notify the "
            "possibility the repology API has changed and might no longer "
            "match what this client expects"
        )
    return ParsedProjectsPage(package_rows, next_query_project, processed_ids)
