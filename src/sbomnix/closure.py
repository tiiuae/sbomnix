#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Dependency closure helpers shared by SBOM generation paths."""

import pandas as pd

from common import columns as cols

DEPENDENCY_COLUMNS = [
    cols.SRC_PATH,
    "src_pname",
    cols.TARGET_PATH,
    "target_pname",
]


def dependency_paths(df_deps):
    """Return all source and target paths referenced by dependency rows."""
    if df_deps is None or df_deps.empty:
        return set()
    src_paths = df_deps[cols.SRC_PATH].unique().tolist()
    target_paths = df_deps[cols.TARGET_PATH].unique().tolist()
    return set(src_paths + target_paths)


def dependencies_to_depth(df_deps, start_path, depth, columns=DEPENDENCY_COLUMNS):
    """Return dependency rows reachable from ``start_path`` up to ``depth``."""
    if df_deps is None or df_deps.empty:
        return pd.DataFrame(columns=pd.Index(columns))

    rows = []
    visited_edges = set()

    def walk(target_path, curr_depth=0):
        curr_depth += 1
        if curr_depth > depth:
            return
        df_matches = df_deps[df_deps[cols.TARGET_PATH] == target_path]
        if df_matches.empty:
            return
        for row in df_matches.to_dict("records"):
            edge_key = (row[cols.TARGET_PATH], row[cols.SRC_PATH])
            if edge_key in visited_edges:
                continue
            visited_edges.add(edge_key)
            rows.append(row)
            walk(row[cols.SRC_PATH], curr_depth)

    walk(start_path)
    if not rows:
        return pd.DataFrame(columns=pd.Index(columns))
    return pd.DataFrame.from_records(rows, columns=pd.Index(columns))


def derivation_dependencies_df(drv_infos):
    """Return build-time dependency edges from recursive derivation JSON."""
    rows = []
    for target_path, drv_info in drv_infos.items():
        for src_path in _iter_input_drv_paths(drv_info):
            rows.append(
                {
                    cols.SRC_PATH: src_path,
                    "src_pname": store_path_label(src_path),
                    cols.TARGET_PATH: target_path,
                    "target_pname": store_path_label(target_path),
                }
            )
    return dependency_rows_to_dataframe(rows)


def dependency_rows_to_dataframe(rows, columns=DEPENDENCY_COLUMNS):
    """Return sorted dependency dataframe from row dictionaries."""
    df_deps = pd.DataFrame.from_records(rows, columns=pd.Index(columns))
    if not df_deps.empty:
        df_deps.drop_duplicates(inplace=True)
        df_deps.sort_values(
            by=["src_pname", cols.SRC_PATH, "target_pname", cols.TARGET_PATH],
            inplace=True,
        )
    return df_deps


def store_path_label(path):
    """Return the nix-store graph-style label for a store path."""
    basename = str(path).rstrip("/").rsplit("/", maxsplit=1)[-1]
    _hash, separator, name = basename.partition("-")
    return name if separator else basename


def _iter_input_drv_paths(drv_info):
    """Yield input derivation paths from old and new derivation JSON formats."""
    inputs = drv_info.get("inputs", {})
    if isinstance(inputs, dict):
        drvs = inputs.get("drvs", {})
        if isinstance(drvs, dict):
            yield from drvs
    input_drvs = drv_info.get("inputDrvs", {})
    if isinstance(input_drvs, dict):
        yield from input_drvs
