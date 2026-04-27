#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Python script to query and visualize nix package dependencies."""

import logging
from importlib import import_module

import pandas as pd

from common.df import df_to_csv_file
from common.log import LOG, LOG_SPAM
from common.proc import exec_cmd
from sbomnix.nix import find_deriver

nixgraph_parsing = import_module("nixgraph.parsing")
nixgraph_render = import_module("nixgraph.render")
nixgraph_store = import_module("nixgraph.store")

NixDependencyGraph = nixgraph_render.NixDependencyGraph


class NixDependencies:
    """Parse nix package dependencies."""

    def __init__(self, nix_path, buildtime=False):
        LOG.debug("nix_path: %s", nix_path)
        self.dependencies = set()
        self.dtype = "buildtime" if buildtime else "runtime"
        LOG.info("Loading %s dependencies referenced by '%s'", self.dtype, nix_path)
        drv_path = _find_deriver(nix_path)
        self.nix_store_path = _get_nix_store_path(drv_path)
        if buildtime:
            self.start_path = drv_path
            self._parse_buildtime_dependencies(drv_path)
        else:
            self.start_path = _find_outpath(drv_path)
            self._parse_runtime_dependencies(drv_path)
        if len(self.dependencies) <= 0:
            LOG.info("No %s dependencies", self.dtype)

    def _parse_runtime_dependencies(self, drv_path):
        nix_query_out = nixgraph_store.runtime_query_output(
            drv_path,
            exec_cmd_fn=exec_cmd,
        )
        LOG.log(LOG_SPAM, "nix_query_out: %s", nix_query_out)
        self._parse_nix_query_out(nix_query_out)

    def _parse_buildtime_dependencies(self, drv_path):
        nix_query_out = nixgraph_store.buildtime_query_output(
            drv_path,
            exec_cmd_fn=exec_cmd,
        )
        LOG.log(LOG_SPAM, "nix_query_out: %s", nix_query_out)
        self._parse_nix_query_out(nix_query_out)

    def _parse_nix_query_out(self, nix_query_out):
        self.dependencies.update(
            nixgraph_parsing.parse_nix_query_out(nix_query_out, self.nix_store_path)
        )

    def to_dataframe(self):
        """Return the dependencies as pandas dataframe."""
        deps = [dep.to_dict() for dep in self.dependencies]
        df = pd.DataFrame.from_records(deps)
        if not df.empty:
            df.sort_values(
                by=["src_pname", "src_path", "target_pname", "target_path"],
                inplace=True,
            )
        if LOG.level <= logging.DEBUG:
            df_to_csv_file(df, f"nixgraph_deps_{self.dtype}.csv")
        return df

    def graph(self, args):
        """Draw the dependencies as directed graph."""
        digraph = NixDependencyGraph(self.to_dataframe())
        return digraph.draw(self.start_path, args)


def _get_nix_store_path(nix_path):
    """Return nix store path given derivation or out-path."""
    return nixgraph_store.get_nix_store_path(nix_path, log=LOG)


def _find_deriver(nix_path):
    """Resolve a nix store path or output path to its deriver."""
    return nixgraph_store.find_deriver_path(
        nix_path,
        find_deriver_fn=find_deriver,
        log=LOG,
    )


def _find_outpath(nix_path):
    """Resolve derivation output path from a derivation path."""
    return nixgraph_store.find_output_path(
        nix_path,
        exec_cmd_fn=exec_cmd,
        log=LOG,
    )
