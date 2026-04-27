#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Indexed dependency lookups for SBOM export."""

from dataclasses import dataclass, field

import pandas as pd


def _sorted_unique(values):
    return sorted({value for value in values if value})


def _normalize_outputs(outputs):
    if isinstance(outputs, (list, tuple)):
        return [output for output in outputs if output]
    if isinstance(outputs, str) and outputs:
        return [outputs]
    return []


def _group_dependency_rows(df, dep_col):
    if df.empty:
        return {}
    return {
        target_path: _sorted_unique(group[dep_col].tolist())
        for target_path, group in df.groupby("target_path")
    }


@dataclass
class DependencyIndex:
    """Lookup dependency identifiers without repeated dataframe merges."""

    by_store_path: dict[str, list[str]]
    component_frame: pd.DataFrame
    _uid_maps: dict[str, dict[str, str]] = field(default_factory=dict)

    def lookup(self, drv, uid="store_path"):
        """Return dependency identifiers for ``drv`` using the requested column."""
        dep_store_paths = self.by_store_path.get(drv.store_path, [])
        if not dep_store_paths:
            return None
        if uid == "store_path":
            return dep_store_paths
        uid_map = self._get_uid_map(uid)
        if uid_map is None:
            return None
        self_uid = getattr(drv, uid, None)
        dep_uids = sorted(
            {
                uid_map[dep_store_path]
                for dep_store_path in dep_store_paths
                if dep_store_path in uid_map and uid_map[dep_store_path]
            }
        )
        if self_uid is not None:
            dep_uids = [dep_uid for dep_uid in dep_uids if dep_uid != self_uid]
        return dep_uids or None

    def _get_uid_map(self, uid):
        if uid in self._uid_maps:
            return self._uid_maps[uid]
        if uid not in self.component_frame.columns:
            return None
        uid_map = dict(
            self.component_frame.loc[:, ["store_path", uid]].itertuples(
                index=False,
                name=None,
            )
        )
        self._uid_maps[uid] = uid_map
        return uid_map


def build_dependency_index(df_deps, df_sbomdb, df_sbomdb_outputs_exploded, uid):
    """Build an indexed dependency map for all SBOM components."""
    if df_sbomdb is None or df_sbomdb.empty:
        return DependencyIndex(by_store_path={}, component_frame=pd.DataFrame())

    by_store_path = {drv.store_path: [] for drv in df_sbomdb.itertuples()}
    if df_deps is None or df_deps.empty:
        return DependencyIndex(by_store_path=by_store_path, component_frame=df_sbomdb)

    runtime_sources = df_sbomdb_outputs_exploded.loc[:, ["outputs", uid]].rename(
        columns={uid: "dependency_uid"}
    )
    runtime_edges = df_deps.merge(
        runtime_sources,
        how="inner",
        left_on=["src_path"],
        right_on=["outputs"],
    )
    runtime_by_target = _group_dependency_rows(runtime_edges, "dependency_uid")

    buildtime_sources = df_sbomdb.loc[:, ["store_path"]].copy()
    buildtime_sources["dependency_uid"] = df_sbomdb[uid]
    buildtime_edges = df_deps.merge(
        buildtime_sources,
        how="inner",
        left_on=["src_path"],
        right_on=["store_path"],
    )
    buildtime_by_target = _group_dependency_rows(buildtime_edges, "dependency_uid")

    for drv in df_sbomdb.itertuples():
        deps = set(buildtime_by_target.get(drv.store_path, ()))
        for output in _normalize_outputs(drv.outputs):
            deps.update(runtime_by_target.get(output, ()))
        deps.discard(getattr(drv, uid, None))
        by_store_path[drv.store_path] = sorted(deps)

    return DependencyIndex(
        by_store_path=by_store_path,
        component_frame=df_sbomdb,
    )
