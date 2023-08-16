#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name, too-many-locals, import-error

""" Python script that compares two sboms """

import argparse
import logging
import os
import sys
import pathlib
import json
import pandas as pd
from sbomnix.utils import LOG, df_to_csv_file, set_log_verbosity

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = "Compare CycloneDX or SPDX sbom json files"
    epil = (
        f"Example: ./{os.path.basename(__file__)} "
        "/path/to/sbom.cdx.json /path/to/sbom.cdx.json"
    )
    parser = argparse.ArgumentParser(description=desc, epilog=epil)
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)
    helps = "Path to first sbom json file"
    parser.add_argument("FILE1", help=helps, type=pathlib.Path)
    helps = "Path to second sbom json file"
    parser.add_argument("FILE2", help=helps, type=pathlib.Path)
    helps = (
        "Set the SBOM component attribute(s) used as unique identifier"
        "(default: --uid='name,version')"
    )
    parser.add_argument("--uid", help=helps, type=str, default="name,version")
    return parser.parse_args()


################################################################################


def _sbom_df_from_dict(dict_obj):
    df_ret = pd.DataFrame(dict_obj)
    df_ret.fillna("", inplace=True)
    df_ret = df_ret.astype(str)
    df_ret.sort_values("name", inplace=True, key=lambda col: col.str.lower())
    df_ret.reset_index(drop=True, inplace=True)
    return df_ret


def _parse_sbom_cdx(json_dict):
    components = json_dict["components"] + [json_dict["metadata"]["component"]]
    components_dict = {}
    setcol = components_dict.setdefault
    for cmp in components:
        setcol("uid", []).append(cmp["bom-ref"])
        setcol("name", []).append(cmp["name"])
        setcol("version", []).append(cmp["version"])
    return _sbom_df_from_dict(components_dict)


def _parse_sbom_spdx(json_dict):
    packages = json_dict["packages"]
    packages_dict = {}
    setcol = packages_dict.setdefault
    for cmp in packages:
        setcol("uid", []).append(cmp["SPDXID"])
        setcol("name", []).append(cmp["name"])
        setcol("version", []).append(cmp["versionInfo"])
    return _sbom_df_from_dict(packages_dict)


def _parse_sbom(path):
    with path.open(encoding="utf-8") as inf:
        json_dict = json.loads(inf.read())
        sbom_format = ""
        if "SPDXID" in json_dict:
            sbom_format = "SPDX"
            return _parse_sbom_spdx(json_dict)
        if "bomFormat" in json_dict:
            sbom_format = json_dict["bomFormat"]
            return _parse_sbom_cdx(json_dict)
        LOG.fatal("Unsupported SBOM format: '%s'", sbom_format)
        sys.exit(1)


def _log_rows(df, name):
    for row in df.itertuples(index=False, name=name):
        LOG.info(row)


def _compare_sboms(args, df1, df2):
    """Describe diff of sboms df1 and df2, return True if they are equal"""
    if LOG.level <= logging.DEBUG:
        df_to_csv_file(df1, "df_sbom_file1.csv")
        df_to_csv_file(df2, "df_sbom_file2.csv")

    uid_list = [str(uid) for uid in args.uid.split(",")]
    df1_uidg = df1.groupby(by=uid_list).size().reset_index(name="count")
    df1_non_uniq = df1_uidg[df1_uidg["count"] > 1]

    df2_uidg = df2.groupby(by=uid_list).size().reset_index(name="count")
    df2_non_uniq = df2_uidg[df2_uidg["count"] > 1]

    df_common = pd.merge(left=df1, right=df2, how="inner", on=uid_list)
    df_common.drop_duplicates(subset=uid_list, inplace=True)

    df1_only = pd.merge(left=df1, right=df2, how="left", on=uid_list)
    df1_only = df1_only[df1_only["uid_y"].isna()]
    df1_only.drop_duplicates(subset=uid_list, inplace=True)

    df2_only = pd.merge(left=df2, right=df1, how="left", on=uid_list)
    df2_only = df2_only[df2_only["uid_y"].isna()]
    df2_only.drop_duplicates(subset=uid_list, inplace=True)

    LOG.info("Using uid: '%s'", uid_list)
    LOG.info("")

    LOG.info("FILE1 path '%s'", args.FILE1)
    LOG.info("FILE1 number of unique entries: %s", len(df1_uidg.index))
    if not df1_non_uniq.empty:
        LOG.info("FILE1 number of non-unique entries: %s", len(df1_non_uniq))
        _log_rows(df1_non_uniq, "non_unique")
    LOG.info("")

    LOG.info("FILE2 path '%s'", args.FILE2)
    LOG.info("FILE2 number of unique components: %s", len(df2_uidg.index))
    if not df2_non_uniq.empty:
        LOG.info("FILE2 number of non-unique entries: %s", len(df2_non_uniq))
        _log_rows(df2_non_uniq, "non_unique")
    LOG.info("")

    LOG.info("FILE1 and FILE2 common entries: %s", len(df_common))
    if not df_common.empty:
        _log_rows(df_common[uid_list], "common")
    LOG.info("")

    LOG.info("FILE1 only entries: %s", len(df1_only))
    if not df1_only.empty:
        _log_rows(df1_only[uid_list], "file1_only")
    LOG.info("")

    LOG.info("FILE2 only entries: %s", len(df2_only))
    if not df2_only.empty:
        _log_rows(df2_only[uid_list], "file2_only")
    LOG.info("")

    return len(df1_only) == 0 and len(df2_only) == 0


################################################################################


def main():
    """main entry point"""
    args = getargs()
    set_log_verbosity(args.verbose)
    if not args.FILE1.exists():
        LOG.fatal("Invalid path: '%s'", args.sbom)
        sys.exit(1)
    if not args.FILE2.exists():
        LOG.fatal("Invalid path: '%s'", args.graph)
        sys.exit(1)

    df_sbom_f1 = _parse_sbom(args.FILE1)
    df_sbom_f2 = _parse_sbom(args.FILE2)
    equal = _compare_sboms(args, df_sbom_f1, df_sbom_f2)
    if equal:
        sys.exit(0)
    else:
        sys.exit(1)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
