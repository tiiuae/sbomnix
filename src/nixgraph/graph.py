#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Python script to query and visualize nix package dependencies."""

from common.df import df_to_csv_file
from common.log import LOG, is_debug_enabled
from nixgraph.render import NixDependencyGraph
from nixgraph.store import find_deriver_path
from sbomnix.closure import derivation_dependencies_df
from sbomnix.derivation import load_recursive
from sbomnix.derivers import find_deriver
from sbomnix.runtime import load_runtime_closure


class NixDependencies:
    """Parse nix package dependencies."""

    def __init__(self, nix_path, buildtime=False, drv_path=None, resolve_output=True):
        LOG.debug("nix_path: %s", nix_path)
        # Kept temporarily for SbomBuilder fallback callers; runtime targets
        # are already output paths after CLI resolution.
        del resolve_output
        self.df_dependencies = None
        self.dtype = "buildtime" if buildtime else "runtime"
        LOG.info("Loading %s dependencies referenced by '%s'", self.dtype, nix_path)
        if buildtime and drv_path is None:
            drv_path = find_deriver_path(
                nix_path,
                find_deriver_fn=find_deriver,
                log=LOG,
            )
        if buildtime:
            assert drv_path is not None
            self.start_path = drv_path
            self._parse_buildtime_dependencies(drv_path)
        else:
            self.start_path = nix_path
            self._parse_runtime_dependencies(nix_path)
        if self.df_dependencies is not None and self.df_dependencies.empty:
            LOG.info("No %s dependencies", self.dtype)

    def _parse_runtime_dependencies(self, output_path):
        runtime_closure = load_runtime_closure(output_path)
        self.df_dependencies = runtime_closure.df_deps

    def _parse_buildtime_dependencies(self, drv_path):
        _derivations, drv_infos = load_recursive(drv_path)
        self.df_dependencies = derivation_dependencies_df(drv_infos)

    def to_dataframe(self):
        """Return the dependencies as pandas dataframe."""
        assert self.df_dependencies is not None
        df = self.df_dependencies
        if is_debug_enabled():
            df_to_csv_file(df, f"nixgraph_deps_{self.dtype}.csv")
        return df

    def graph(self, args):
        """Draw the dependencies as directed graph."""
        digraph = NixDependencyGraph(self.to_dataframe())
        return digraph.draw(self.start_path, args)
