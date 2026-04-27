#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared report and file helpers for vulnxscan."""

import json
import re

import pandas as pd

from common.log import LOG

################################################################################


def _reformat_scanner(val):
    if val and not pd.isnull(val):
        return "1"
    return "0"


def _vuln_sortcol(row):
    # Return a string that should make the vulns we want to see high
    # on the report list to bubble up when sorted in ascending order based
    # on the returned string
    match = re.match(r".*[A-Za-z][-_]([1-2][0-9]{3})[-_]([0-9]+).*", row.vuln_id)
    if match:
        year = match.group(1)
        number = str(match.group(2)).zfill(10)
        return f"{year}A{number}"
    if row.modified and not pd.isnull(row.modified):
        return f"{row.modified.year}A{int(row.modified.timestamp())}"
    return str(row.vuln_id)


def _vuln_url(row):
    osv_url = "https://osv.dev/"
    nvd_url = "https://nvd.nist.gov/vuln/detail/"
    if row.vuln_id.lower().startswith("cve"):
        return f"{nvd_url}{row.vuln_id}"
    if getattr(row, "osv", False) or ("osv" in getattr(row, "scanner", [])):
        return f"{osv_url}{row.vuln_id}"
    return ""


def _vuln_source(row):
    if row.vuln_id.lower().startswith("cve"):
        return "NVD"
    if getattr(row, "osv", False) or ("osv" in getattr(row, "scanner", [])):
        return "OSV"
    return ""


def _is_patched(row):
    if row.vuln_id and str(row.vuln_id).lower() in str(row.patches).lower():
        patches = row.patches.split()
        patch = [p for p in patches if str(row.vuln_id).lower() in str(p).lower()]
        LOG.info("%s for '%s' is patched with: %s", row.vuln_id, row.package, patch)
        return True
    return False


def _is_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            json_obj = json.load(f)
            if json_obj:
                return True
            return False
    except (json.JSONDecodeError, OSError, UnicodeError):
        return False
