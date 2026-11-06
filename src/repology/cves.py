# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for parsing Repology CVE pages."""

import re
from typing import NoReturn

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup

import repology.exceptions
from common import columns as cols
from common.log import LOG, LOG_SPAM
from common.versioning import parse_version

_REQUIRED_CVE_HEADERS = {"Affected version(s)", "CVE ID"}
_EMPTY_CVE_RESPONSE_PREFIX = "No CVEs known for this project."


def _raise_unexpected_response(log, error=None) -> NoReturn:
    detail = "malformed Repology CVE response"
    log.fatal("Unexpected response: %s", detail)
    raise repology.exceptions.RepologyUnexpectedResponse(detail) from error


def _is_unbounded(range_ver):
    # Repology writes open-ended ranges with an infinity endpoint,
    # e.g. "(-∞, 1.0.2)"
    return range_ver.strip() in {"-∞", "+∞", "∞"}


_SIMPLE_VERSION = re.compile(r"^(?P<nums>\d+(?:\.\d+)*)(?P<letters>[a-z]*)$")


def _simple_version_key(ver_str):
    # Dotted numbers with an optional letter suffix, e.g. "1.2.3" or the
    # OpenSSL style "0.9.8zh", where the letters order after the bare number
    match = _SIMPLE_VERSION.match(ver_str.strip())
    if not match:
        return None
    nums = [int(num) for num in match.group("nums").split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    return (tuple(nums), match.group("letters"))


def _compare_versions(ver_a, ver_b):
    """
    Return -1, 0 or 1 comparing the two version strings, or None if they
    can not be compared reliably.
    """
    key_a = _simple_version_key(ver_a)
    key_b = _simple_version_key(ver_b)
    if key_a is None or key_b is None:
        return None
    return (key_a > key_b) - (key_a < key_b)


def _is_same_version(version, version_local, impacted_version_text):
    cmp = _compare_versions(version, impacted_version_text)
    if cmp is not None:
        return cmp == 0
    return parse_version(impacted_version_text) == version_local


def is_affected(version, affected_ver_str, *, log=LOG, log_spam=LOG_SPAM):
    """
    Return True if version number is included in the repology affected version
    string. Also returns true if the versions in a range can not be compared
    reliably, in order to avoid false negatives.
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
        beg_affected = _is_unbounded(impacted_group[1])
        if not beg_affected:
            cmp = _compare_versions(version, impacted_group[1])
            if cmp is None:
                return True
            beg_affected = cmp > 0 or (cmp == 0 and beg_ind == "[")
        end_ind = impacted_group[3]
        end_affected = _is_unbounded(impacted_group[2])
        if not end_affected:
            cmp = _compare_versions(version, impacted_group[2])
            if cmp is None:
                return True
            end_affected = cmp < 0 or (cmp == 0 and end_ind == "]")
        if beg_affected and end_affected:
            return True
    ver_one = r"(?<= )(?<!\()(?P<version>\d[^ $)\]]+)(?= )"
    matches = re.findall(ver_one, affected_ver_str)
    log.log(log_spam, "Parsed single version(s): %s", matches)
    for impacted_version_text in matches:
        if _is_same_version(version, version_local, impacted_version_text):
            return True
    return False


def parse_cve_html(html_text, pkg_name, pkg_version, *, log=LOG, log_spam=LOG_SPAM):
    """Parse a Repology CVE page into a dataframe."""
    soup = BeautifulSoup(html_text, "html.parser")
    tables = soup.find_all("table")
    if not tables:
        empty_alert = soup.find("div", {"class": "alert alert-success"})
        if empty_alert and empty_alert.get_text(" ", strip=True).startswith(
            _EMPTY_CVE_RESPONSE_PREFIX
        ):
            log.debug("No CVEs known for this project")
            return pd.DataFrame()
        _raise_unexpected_response(log)

    cve_table = tables[0]
    if cve_table.thead is None or cve_table.tbody is None:
        _raise_unexpected_response(log)
    headers = {
        header.text: idx for idx, header in enumerate(cve_table.thead.find_all("th"))
    }
    try:
        required_cells = max(headers[name] for name in _REQUIRED_CVE_HEADERS) + 1
    except KeyError as error:
        _raise_unexpected_response(log, error)
    cve_table_rows = cve_table.tbody.find_all("tr")
    if not cve_table_rows:
        _raise_unexpected_response(log)
    log.log(log_spam, headers)

    cve_dict = {}
    for row in cve_table_rows:
        cells = row.find_all("td")
        if len(cells) < required_cells:
            _raise_unexpected_response(log)
        affected_versions = row.find_all("span", {"class": "version version-outdated"})
        if not affected_versions:
            continue
        cve_row = cells[headers["CVE ID"]]
        ver_row = cells[headers["Affected version(s)"]]
        log.log(log_spam, "CVE: %s", cve_row)
        log.log(log_spam, "Versions: %s", ver_row)
        if not is_affected(pkg_version, ver_row.text, log=log, log_spam=log_spam):
            continue
        cve_info = cve_row.text.strip().split("\n")
        if not cve_info or not cve_info[0]:
            _raise_unexpected_response(log)
        log.debug("CVE info: %s", cve_info)
        cve_dict.setdefault(cols.PACKAGE, []).append(pkg_name)
        cve_dict.setdefault(cols.VERSION, []).append(pkg_version)
        cve_dict.setdefault("cve", []).append(cve_info[0])

    df = pd.DataFrame.from_dict(cve_dict)
    df.replace(np.nan, "", regex=True, inplace=True)
    df.drop_duplicates(keep="first", inplace=True)
    return df
