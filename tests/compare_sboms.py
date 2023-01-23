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
from sbomnix.utils import (
    setup_logging,
    LOGGER_NAME,
    df_to_csv_file,
)

###############################################################################

_LOG = logging.getLogger(LOGGER_NAME)

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = "Compare two CycloneDX sbom json files"
    epil = (
        f"Example: ./{os.path.basename(__file__)} "
        "/path/to/sbom1.json /path/to/sbom2.json"
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


def _parse_sbom(path):
    with path.open(encoding="utf-8") as inf:
        json_dict = json.loads(inf.read())

        components = json_dict["components"] + [json_dict["metadata"]["component"]]
        components_dict = {}
        setcol = components_dict.setdefault
        for cmp in components:
            setcol("bom_ref", []).append(cmp["bom-ref"])
            setcol("name", []).append(cmp["name"])
            setcol("version", []).append(cmp["version"])

        df_components = pd.DataFrame(components_dict)
        df_components.fillna("", inplace=True)
        df_components = df_components.astype(str)
        df_components.sort_values("name", inplace=True, key=lambda col: col.str.lower())
        df_components.reset_index(drop=True, inplace=True)
        return df_components


def _log_rows(df, name):
    for row in df.itertuples(index=False, name=name):
        _LOG.info(row)


def _compare_sboms(args, df1, df2):
    """Describe diff of sboms df1 and df2, return True if they are equal"""
    if _LOG.level <= logging.DEBUG:
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
    df1_only = df1_only[df1_only["bom_ref_y"].isna()]
    df1_only.drop_duplicates(subset=uid_list, inplace=True)

    df2_only = pd.merge(left=df2, right=df1, how="left", on=uid_list)
    df2_only = df2_only[df2_only["bom_ref_y"].isna()]
    df2_only.drop_duplicates(subset=uid_list, inplace=True)

    _LOG.info("Using uid: '%s'", uid_list)
    _LOG.info("")

    _LOG.info("FILE1 path '%s'", args.FILE1)
    _LOG.info("FILE1 number of unique components: %s", len(df1_uidg.index))
    if not df1_non_uniq.empty:
        _LOG.info("FILE1 number of non-unique components: %s", len(df1_non_uniq))
        _log_rows(df1_non_uniq, "non_unique")
    _LOG.info("")

    _LOG.info("FILE2 path '%s'", args.FILE2)
    _LOG.info("FILE2 number of unique components: %s", len(df2_uidg.index))
    if not df2_non_uniq.empty:
        _LOG.info("FILE2 number of non-unique components: %s", len(df2_non_uniq))
        _log_rows(df2_non_uniq, "non_unique")
    _LOG.info("")

    _LOG.info("FILE1 and FILE2 common components: %s", len(df_common))
    if not df_common.empty:
        _log_rows(df_common[uid_list], "common")
    _LOG.info("")

    _LOG.info("FILE1 only components: %s", len(df1_only))
    if not df1_only.empty:
        _log_rows(df1_only[uid_list], "file1_only")
    _LOG.info("")

    _LOG.info("FILE2 only components: %s", len(df2_only))
    if not df2_only.empty:
        _log_rows(df2_only[uid_list], "file2_only")
    _LOG.info("")

    return len(df1_only) == 0 and len(df2_only) == 0


################################################################################


def main():
    """main entry point"""
    args = getargs()
    setup_logging(args.verbose)
    if not args.FILE1.exists():
        _LOG.fatal("Invalid path: '%s'", args.sbom)
        sys.exit(1)
    if not args.FILE2.exists():
        _LOG.fatal("Invalid path: '%s'", args.graph)
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
