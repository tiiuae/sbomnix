# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for running and parsing ``nix-visualize`` output."""

import pathlib
from tempfile import NamedTemporaryFile

from common import columns as cols
from common.df import df_from_csv_file
from common.log import LOG, LOG_VERBOSE
from common.package_names import nix_to_repology_pkg_name
from common.proc import exec_cmd


def run_nix_visualize(
    target_path,
    *,
    exec_cmd_fn=exec_cmd,
    tempfile_factory=NamedTemporaryFile,
    log=LOG,
):
    """Run ``nix-visualize`` and return the generated CSV path."""
    log.log(LOG_VERBOSE, "Running nix-visualize")
    with tempfile_factory(
        delete=False,
        prefix="nix-visualize_",
        suffix=".csv",
    ) as outfile:
        cmd = ["nix-visualize", f"--output={outfile.name}", target_path]
        exec_cmd_fn(cmd)
        return pathlib.Path(outfile.name)


def nix_visualize_csv_to_df(csvpath):
    """Convert ``nix-visualize`` CSV output into Repology-comparable rows."""
    df = df_from_csv_file(csvpath)
    re_split = (
        r"^[^-]+?-"
        r"(.+?)-"
        r"(\d[-_.0-9pf]*g?b?(?:pre[0-9])*(?:\+git[0-9]*)?)"
        r"(?:-lib|-bin|-env|-man|-su|-dev|-doc|-info|-nc|-host|-p[0-9]+|\.drv|)"
        r"$"
    )
    df[[cols.PACKAGE, cols.VERSION]] = df[cols.RAW_NAME].str.extract(
        re_split,
        expand=True,
    )
    df[cols.PACKAGE] = df.apply(
        lambda row: nix_to_repology_pkg_name(row.package),
        axis=1,
    )
    return df
