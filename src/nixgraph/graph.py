#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Python script to query and visualize nix package dependencies."""

from dataclasses import dataclass

import pandas as pd

from common.df import df_to_csv_file
from common.log import LOG, is_debug_enabled
from nixgraph.render import NixDependencyGraph
from sbomnix.closure import derivation_dependencies_df
from sbomnix.derivation import load_recursive
from sbomnix.derivers import require_deriver
from sbomnix.runtime import load_runtime_closure


@dataclass(frozen=True)
class LoadedDependencies:
    """Dependency dataframe and graph traversal start path."""

    start_path: str
    df: pd.DataFrame
    dtype: str


def load_dependencies(nix_path, buildtime=False):
    """Load nixgraph dependency rows from structured Nix data."""
    LOG.debug("nix_path: %s", nix_path)
    dtype = "buildtime" if buildtime else "runtime"
    LOG.info("Loading %s dependencies referenced by '%s'", dtype, nix_path)
    if buildtime:
        drv_path = require_deriver(nix_path)
        _derivations, drv_infos = load_recursive(drv_path)
        loaded = LoadedDependencies(
            start_path=drv_path,
            df=derivation_dependencies_df(drv_infos),
            dtype=dtype,
        )
    else:
        runtime_closure = load_runtime_closure(nix_path)
        loaded = LoadedDependencies(
            start_path=nix_path,
            df=runtime_closure.df_deps,
            dtype=dtype,
        )
    if loaded.df.empty:
        LOG.info("No %s dependencies", dtype)
    return loaded


def draw_dependencies(loaded, args):
    """Draw loaded dependencies as a directed graph."""
    if is_debug_enabled():
        df_to_csv_file(loaded.df, f"nixgraph_deps_{loaded.dtype}.csv")
    digraph = NixDependencyGraph(loaded.df)
    return digraph.draw(loaded.start_path, args)
