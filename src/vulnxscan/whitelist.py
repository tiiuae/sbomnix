#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""
Utility functions when dealing with whitelists
"""

################################################################################

# Whitelist

import sys

from common.utils import LOG, LOG_SPAM, df_from_csv_file, df_log


def load_whitelist(whitelist_csv_path):
    """
    Load vulnerability whitelist from the given path. Returns None
    if the whitelist is not a valid vulnerability whitelist. Otherwise
    returns whitelist_csv_path as dataframe.
    """
    df = df_from_csv_file(whitelist_csv_path, exit_on_error=False)
    if df is None:
        return None
    # Whitelist must have the following columns
    if not set(["vuln_id", "comment"]).issubset(df.columns):
        LOG.warning("Whitelist csv missing required columns")
        return None
    if "whitelist" in df.columns:
        # Interpret possible string values in "whitelist" column
        # to boolean as follows:
        df["whitelist"] = df["whitelist"].replace({"": True})
        df["whitelist"] = (
            df["whitelist"].astype(str).replace({"False": False, "0": False})
        )
        df["whitelist"] = df["whitelist"].astype("bool")
    return df


def df_apply_whitelist(df_whitelist, df_vulns):
    """
    Apply df_whitelist to vulnerabilities in df_vulns, changing df_vulns
    in-place.
    Adds columns "whitelist" and "whitelist_comment" to df_vulns based
    on whitelisting regular expressions in column df_whitelist["vuln_id"].
    If df_whitelist["package"] exists and is not empty, require strict
    match in df_whitelist["package"] and df_vulns["package"].
    If df_whitelist["whitelist"] exists and is False, do *not* whitelist
    the entry even if the rule matches, but only apply the column
    "whitelist_comment" to matching entries.
    """
    # Add default values to whitelist columns
    df_vulns["whitelist"] = False
    df_vulns["whitelist_comment"] = ""
    if "vuln_id" not in df_vulns:
        LOG.fatal("Missing 'vuln_id' column from df_vulns")
        sys.exit(1)
    if "vuln_id" not in df_whitelist:
        LOG.warning("Whitelist ignored: missing 'vuln_id' column from whitelist")
        return
    check_pkg_name = False
    if "package" in df_whitelist.columns and "package" in df_vulns.columns:
        check_pkg_name = True
    check_whitelist = False
    if "whitelist" in df_whitelist.columns:
        check_whitelist = True
    # Iterate rows in df_whitelist in reverse order so the whitelist rules
    # on top of the file get higher priority
    df_whitelist_rev = df_whitelist[::-1]
    for whitelist_entry in df_whitelist_rev.itertuples():
        LOG.log(LOG_SPAM, "whitelist_entry: %s", whitelist_entry)
        regex = str(whitelist_entry.vuln_id).strip()
        LOG.log(LOG_SPAM, "whitelist regex: %s", regex)
        df_matches = df_vulns["vuln_id"].str.fullmatch(regex)
        if check_pkg_name and whitelist_entry.package:
            LOG.log(LOG_SPAM, "filtering by pacakge name: %s", whitelist_entry.package)
            df_matches = df_matches & (df_vulns["package"] == whitelist_entry.package)
        df_vulns.loc[df_matches, "whitelist"] = True
        if check_whitelist:
            LOG.log(LOG_SPAM, "entry[whitelist]=%s", bool(whitelist_entry.whitelist))
            df_vulns.loc[df_matches, "whitelist"] = bool(whitelist_entry.whitelist)
        df_vulns.loc[df_matches, "whitelist_comment"] = whitelist_entry.comment
        LOG.log(LOG_SPAM, "matches %s vulns", len(df_vulns[df_matches]))
        df_log(df_vulns[df_matches], LOG_SPAM)


def df_drop_whitelisted(df):
    """
    Drop whitelisted vulnerabilities from `df` as well as
    the related columns.
    """
    if "whitelist" in df.columns:
        # Convert possible string to boolean
        df = df[~df["whitelist"]]
        df = df.drop("whitelist", axis=1)
    if "whitelist_comment" in df.columns:
        df = df.drop("whitelist_comment", axis=1)
    return df
