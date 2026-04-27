#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Python script to query and visualize nix package dependencies."""

import pandas as pd

from common.df import df_to_csv_file
from common.log import LOG, LOG_SPAM, is_debug_enabled
from common.proc import exec_cmd
from nixgraph.parsing import parse_nix_query_out
from nixgraph.render import NixDependencyGraph
from nixgraph.store import (
    buildtime_query_output,
    find_deriver_path,
    find_output_path,
    get_nix_store_path,
    runtime_query_output,
)
from sbomnix.nix import find_deriver


class NixDependencies:
    """Parse nix package dependencies."""

    def __init__(self, nix_path, buildtime=False):
        LOG.debug("nix_path: %s", nix_path)
        self.dependencies = set()
        self.dtype = "buildtime" if buildtime else "runtime"
        LOG.info("Loading %s dependencies referenced by '%s'", self.dtype, nix_path)
        drv_path = find_deriver_path(
            nix_path,
            find_deriver_fn=find_deriver,
            log=LOG,
        )
        self.nix_store_path = get_nix_store_path(drv_path, log=LOG)
        if buildtime:
            self.start_path = drv_path
            self._parse_buildtime_dependencies(drv_path)
        else:
            self.start_path = find_output_path(
                drv_path,
                exec_cmd_fn=exec_cmd,
                log=LOG,
            )
            self._parse_runtime_dependencies(drv_path)
        if len(self.dependencies) <= 0:
            LOG.info("No %s dependencies", self.dtype)

    def _parse_runtime_dependencies(self, drv_path):
        nix_query_out = runtime_query_output(
            drv_path,
            exec_cmd_fn=exec_cmd,
        )
        LOG.log(LOG_SPAM, "nix_query_out: %s", nix_query_out)
        self._parse_nix_query_out(nix_query_out)

    def _parse_buildtime_dependencies(self, drv_path):
        nix_query_out = buildtime_query_output(
            drv_path,
            exec_cmd_fn=exec_cmd,
        )
        LOG.log(LOG_SPAM, "nix_query_out: %s", nix_query_out)
        self._parse_nix_query_out(nix_query_out)

    def _parse_nix_query_out(self, nix_query_out):
        self.dependencies.update(
            parse_nix_query_out(nix_query_out, self.nix_store_path)
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
        if is_debug_enabled():
            df_to_csv_file(df, f"nixgraph_deps_{self.dtype}.csv")
        return df

    def graph(self, args):
        """Draw the dependencies as directed graph."""
        digraph = NixDependencyGraph(self.to_dataframe())
        return digraph.draw(self.start_path, args)
