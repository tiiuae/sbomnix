# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-locals

"""Helpers for parsing Repology CVE pages."""

import re

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup

import repology.exceptions
from common.log import LOG, LOG_SPAM
from common.versioning import parse_version


def is_affected(version, affected_ver_str, *, log=LOG, log_spam=LOG_SPAM):
    """
    Return True if version number is included in the repology affected version
    string. Also returns true if parsing affected version string fails,
    in order to avoid false negatives.
    """
    log.log(log_spam, "Affected version(s): %s", affected_ver_str)
    version_local = parse_version(version)
    if not version_local:
        log.fatal("Unexpected local version string: %s", version)
        raise repology.exceptions.RepologyError
    affected_ver_str = f" {affected_ver_str} "
    ver_group = re.compile(
        r"(?P<beg>[(\[])(?P<begver>[^,]*), *(?P<endver>[^)\]]*)(?P<end>[\])])"
    )
    matches = re.findall(ver_group, affected_ver_str)
    if matches:
        log.log(log_spam, "Parsed group version(s): %s", matches)
    for impacted_group in matches:
        if len(impacted_group) != 4:
            log.fatal("Unexpected version group: %s", affected_ver_str)
            raise repology.exceptions.RepologyUnexpectedResponse
        beg_ind = impacted_group[0]
        beg_ver_parsed = parse_version(impacted_group[1])
        if not beg_ver_parsed:
            return True
        end_ind = impacted_group[3]
        end_ver_parsed = parse_version(impacted_group[2])
        if not end_ver_parsed:
            return True
        beg_affected = False
        end_affected = False
        if (version_local > beg_ver_parsed) or (
            version_local == beg_ver_parsed and beg_ind == "["
        ):
            beg_affected = True
        if (version_local < end_ver_parsed) or (
            version_local == end_ver_parsed and end_ind == "]"
        ):
            end_affected = True
        if beg_affected and end_affected:
            return True
    ver_one = r"(?<= )(?<!\()(?P<version>\d[^ $)]+)(?= )"
    matches = re.findall(ver_one, affected_ver_str)
    log.log(log_spam, "Parsed single version(s): %s", matches)
    for impacted_version in matches:
        impacted_version = parse_version(impacted_version)
        if impacted_version == version_local:
            return True
    return False


def parse_cve_html(html_text, pkg_name, pkg_version, *, log=LOG, log_spam=LOG_SPAM):
    """Parse a Repology CVE page into a dataframe."""
    soup = BeautifulSoup(html_text, "html.parser")
    tables = soup.find_all("table")
    if not tables:
        log.debug("Unexpected response: CVE table missing")
        return pd.DataFrame()
    cve_table = tables[0]
    headers = {}
    for idx, header in enumerate(cve_table.thead.find_all("th")):
        headers[header.text] = idx
    if not headers or "CVE ID" not in headers:
        log.fatal("Unexpected response")
        raise repology.exceptions.RepologyUnexpectedResponse
    log.log(log_spam, headers)
    cve_table_rows = cve_table.tbody.find_all("tr")
    cve_dict = {}
    for row in cve_table_rows:
        affected_versions = row.find_all("span", {"class": "version version-outdated"})
        if not affected_versions:
            continue
        cols = row.find_all("td")
        if not cols:
            continue
        cve_row = cols[headers["CVE ID"]]
        log.log(log_spam, "CVE: %s", cve_row)
        ver_row = cols[headers["Affected version(s)"]]
        log.log(log_spam, "Versions: %s", ver_row)
        if not is_affected(pkg_version, ver_row.text, log=log, log_spam=log_spam):
            continue
        cve_info = cve_row.text.strip().split("\n")
        log.debug("CVE info: %s", cve_info)
        cve_dict.setdefault("package", []).append(pkg_name)
        cve_dict.setdefault("version", []).append(pkg_version)
        cve_dict.setdefault("cve", []).append(cve_info[0])
    df = pd.DataFrame.from_dict(cve_dict)
    df.replace(np.nan, "", regex=True, inplace=True)
    df.drop_duplicates(keep="first", inplace=True)
    return df
