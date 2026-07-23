#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for whitelist handling."""

import pandas as pd

from common import columns as cols
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


def test_whitelist_version_local_matches_report_version_column():
    """version_local rules should match vulnxscan's pre-rename version column."""
    df_whitelist = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "openssl",
                cols.VERSION_LOCAL: "3.0.0",
                cols.COMMENT: "only openssl 3.0.0",
            }
        ]
    )
    df_vulns = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "openssl",
                cols.VERSION: "3.0.0",
            },
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "openssl",
                cols.VERSION: "3.1.0",
            },
        ]
    )

    df_apply_whitelist(df_whitelist, df_vulns)

    assert df_vulns[cols.WHITELIST].tolist() == [True, False]
    assert df_vulns[cols.WHITELIST_COMMENT].tolist() == [
        "only openssl 3.0.0",
        "",
    ]


def test_whitelist_version_local_matches_renamed_version_local_column():
    """version_local rules should also work on already-renamed dataframes."""
    df_whitelist = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "openssl",
                cols.VERSION_LOCAL: "3.0.0",
                cols.COMMENT: "only openssl 3.0.0",
            }
        ]
    )
    df_vulns = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "openssl",
                cols.VERSION_LOCAL: "3.0.0",
            },
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "openssl",
                cols.VERSION_LOCAL: "3.1.0",
            },
        ]
    )

    df_apply_whitelist(df_whitelist, df_vulns)

    assert df_vulns[cols.WHITELIST].tolist() == [True, False]
    assert df_vulns[cols.WHITELIST_COMMENT].tolist() == [
        "only openssl 3.0.0",
        "",
    ]


def test_whitelist_empty_version_local_keeps_existing_broad_match():
    """Empty version_local cells should not restrict older whitelist rules."""
    df_whitelist = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "openssl",
                cols.VERSION_LOCAL: "",
                cols.COMMENT: "all openssl versions",
            }
        ]
    )
    df_vulns = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "openssl",
                cols.VERSION: "3.0.0",
            },
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "openssl",
                cols.VERSION: "3.1.0",
            },
        ]
    )

    df_apply_whitelist(df_whitelist, df_vulns)

    assert df_vulns[cols.WHITELIST].tolist() == [True, True]
    assert df_vulns[cols.WHITELIST_COMMENT].tolist() == [
        "all openssl versions",
        "all openssl versions",
    ]


def test_whitelist_version_local_is_exact_not_regex():
    """version_local should treat regex metacharacters as ordinary characters."""
    df_whitelist = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "openssl",
                cols.VERSION_LOCAL: "3.0.0",
                cols.COMMENT: "only exact version",
            }
        ]
    )
    df_vulns = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "openssl",
                cols.VERSION: "3.0.0",
            },
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "openssl",
                cols.VERSION: "3x0x0",
            },
        ]
    )

    df_apply_whitelist(df_whitelist, df_vulns)

    assert df_vulns[cols.WHITELIST].tolist() == [True, False]
    assert df_vulns[cols.WHITELIST_COMMENT].tolist() == [
        "only exact version",
        "",
    ]


def test_whitelist_version_local_regex_matches_report_version_column():
    """version_local_regex should fullmatch vulnxscan's pre-rename version column."""
    df_whitelist = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "jq",
                cols.VERSION_LOCAL_REGEX: r".*-binlore",
                cols.COMMENT: "generated binlore artifact",
            }
        ]
    )
    df_vulns = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "jq",
                cols.VERSION: "1.8.1-binlore",
            },
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "jq",
                cols.VERSION: "1.8.1",
            },
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "jq",
                cols.VERSION: "1.8.1-binlore-extra",
            },
        ]
    )

    df_apply_whitelist(df_whitelist, df_vulns)

    assert df_vulns[cols.WHITELIST].tolist() == [True, False, False]
    assert df_vulns[cols.WHITELIST_COMMENT].tolist() == [
        "generated binlore artifact",
        "",
        "",
    ]


def test_whitelist_version_local_regex_matches_renamed_version_local_column():
    """version_local_regex should work on already-renamed dataframes."""
    df_whitelist = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "go",
                cols.VERSION_LOCAL_REGEX: r".*-linux-amd64-bootstrap",
                cols.COMMENT: "bootstrap go artifact",
            }
        ]
    )
    df_vulns = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "go",
                cols.VERSION_LOCAL: "1.22.12-linux-amd64-bootstrap",
            },
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "go",
                cols.VERSION_LOCAL: "1.22.12",
            },
        ]
    )

    df_apply_whitelist(df_whitelist, df_vulns)

    assert df_vulns[cols.WHITELIST].tolist() == [True, False]
    assert df_vulns[cols.WHITELIST_COMMENT].tolist() == [
        "bootstrap go artifact",
        "",
    ]


def test_whitelist_empty_version_local_regex_keeps_existing_broad_match():
    """Empty version_local_regex cells should not restrict whitelist rules."""
    df_whitelist = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "jq",
                cols.VERSION_LOCAL_REGEX: "",
                cols.COMMENT: "all jq versions",
            }
        ]
    )
    df_vulns = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "jq",
                cols.VERSION: "1.8.1-binlore",
            },
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "jq",
                cols.VERSION: "1.8.1",
            },
        ]
    )

    df_apply_whitelist(df_whitelist, df_vulns)

    assert df_vulns[cols.WHITELIST].tolist() == [True, True]
    assert df_vulns[cols.WHITELIST_COMMENT].tolist() == [
        "all jq versions",
        "all jq versions",
    ]


def test_whitelist_version_filters_are_cumulative():
    """Exact and regex version filters should both apply when both are set."""
    df_whitelist = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "jq",
                cols.VERSION_LOCAL: "1.8.1-binlore",
                cols.VERSION_LOCAL_REGEX: r".*-binlore",
                cols.COMMENT: "exact binlore artifact",
            }
        ]
    )
    df_vulns = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "jq",
                cols.VERSION: "1.8.1-binlore",
            },
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "jq",
                cols.VERSION: "1.8.1-env",
            },
        ]
    )

    df_apply_whitelist(df_whitelist, df_vulns)

    assert df_vulns[cols.WHITELIST].tolist() == [True, False]
