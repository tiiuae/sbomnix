#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Dependency closure helpers shared by SBOM generation paths."""

from dataclasses import dataclass
from typing import Any, Callable, Iterable

import pandas as pd

from common import columns as cols

DEPENDENCY_COLUMNS = [
    cols.SRC_PATH,
    "src_pname",
    cols.TARGET_PATH,
    "target_pname",
]


@dataclass(frozen=True)
class DependencyWalkRow:
    """One dependency row reached during graph traversal."""

    row: dict[str, Any]
    depth: int


def dependency_paths(df_deps):
    """Return all source and target paths referenced by dependency rows."""
    if df_deps is None or df_deps.empty:
        return set()
    src_paths = df_deps[cols.SRC_PATH].unique().tolist()
    target_paths = df_deps[cols.TARGET_PATH].unique().tolist()
    return set(src_paths + target_paths)


def dependencies_to_depth(df_deps, start_path, depth, columns=DEPENDENCY_COLUMNS):
    """Return dependency rows reachable from ``start_path`` up to ``depth``."""
    rows = [walked.row for walked in walk_dependency_rows(df_deps, start_path, depth)]
    if not rows:
        return pd.DataFrame(columns=pd.Index(columns))
    return pd.DataFrame.from_records(rows, columns=pd.Index(columns))


def walk_dependency_rows(
    df_deps,
    start_paths: str | Iterable[str],
    depth,
    *,
    inverse=False,
    stop_at: Callable[[dict[str, Any]], bool] | None = None,
):
    """Return dependency rows reached by a depth-limited graph walk."""
    if df_deps is None or df_deps.empty:
        return []

    if isinstance(start_paths, str):
        normalized_start_paths = [start_paths]
    else:
        normalized_start_paths = list(start_paths)

    match_column = cols.SRC_PATH if inverse else cols.TARGET_PATH
    next_column = cols.TARGET_PATH if inverse else cols.SRC_PATH
    rows = []
    visited_edges = set()

    def walk(current_path, curr_depth=0):
        curr_depth += 1
        if curr_depth > depth:
            return
        df_matches = df_deps[df_deps[match_column] == current_path]
        if df_matches.empty:
            return
        for row in df_matches.to_dict("records"):
            edge_key = (row[cols.TARGET_PATH], row[cols.SRC_PATH])
            if edge_key in visited_edges:
                continue
            visited_edges.add(edge_key)
            rows.append(DependencyWalkRow(row=row, depth=curr_depth))
            if stop_at is not None and stop_at(row):
                continue
            walk(row[next_column], curr_depth)

    for start_path in dict.fromkeys(normalized_start_paths):
        walk(start_path)
    return rows


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
    """Return the Nix store graph-style label for a store path."""
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
