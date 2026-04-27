#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for whitelist handling."""

from common.df import df_from_csv_file
from tests.testpaths import RESOURCES_DIR
from tests.testutils import df_difference, df_to_string
from vulnxscan.whitelist import df_apply_whitelist, load_whitelist


def test_whitelist():
    """Test applying whitelist to vulnerability csv file."""
    whitelist_csv = RESOURCES_DIR / "whitelist.csv"
    assert whitelist_csv.exists()
    vulns_csv = RESOURCES_DIR / "vulns.csv"
    assert vulns_csv.exists()

    df_whitelist = load_whitelist(whitelist_csv)
    assert df_whitelist is not None
    df_vulns = df_from_csv_file(vulns_csv)
    assert df_vulns is not None

    df_vuln_id_copy = df_vulns.copy()[["vuln_id", "package"]]
    df_apply_whitelist(df_whitelist, df_vuln_id_copy)

    df_diff = df_difference(df_vulns.astype(str), df_vuln_id_copy.astype(str))
    assert df_diff.empty, df_to_string(df_diff)
