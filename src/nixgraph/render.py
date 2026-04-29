#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for traversing and rendering nix dependency graphs."""

import html
import os
from typing import Any

import graphviz as gv
import pandas as pd

from common import columns as cols
from common.df import df_regex_filter, df_to_csv_file
from common.log import LOG, LOG_SPAM
from common.regex import regex_match
from sbomnix.closure import walk_dependency_rows

DBG_INDENT = "    "


class NixDependencyGraph:
    """Draw nix package dependencies as graph."""

    def __init__(self, df_dependencies):
        self.df = df_dependencies
        self.digraph = None
        self.df_out_csv = None
        self.maxdepth = 1
        self.inverse_regex = None
        self.until_regex = None
        self.colorize_regex = None
        self.pathnames = False

    def draw(self, start_path, args):
        """Draw dependency graph."""
        self._init_df_out(args)
        self.maxdepth = args.depth if hasattr(args, "depth") else 1
        self.inverse_regex = args.inverse if hasattr(args, "inverse") else None
        self.until_regex = args.until if hasattr(args, "until") else None
        self.colorize_regex = args.colorize if hasattr(args, "colorize") else None
        self.pathnames = args.pathnames if hasattr(args, "pathnames") else False
        self.digraph = gv.Digraph()
        self.digraph.attr("graph", rankdir="LR")
        self.digraph.attr("node", shape="box")
        self.digraph.attr("node", style="rounded")
        self.digraph.attr("node", margin="0.3,0.1")
        self.digraph.attr("graph", concentrate="false")
        initlen = len(self.digraph.body)

        walked_rows = self._walk_rows(start_path)
        if self.df_out_csv is not None:
            self.df_out_csv = self._walked_rows_to_dataframe(walked_rows)
        else:
            for walked in walked_rows:
                self._draw_row(walked.row, walked.depth)

        if len(self.digraph.body) > initlen:
            self._render(args.out)
        elif self.df_out_csv is not None and not self.df_out_csv.empty:
            if hasattr(args, "return_df") and args.return_df:
                LOG.debug("Returning graph as dataframe")
                return self.df_out_csv
            df_to_csv_file(self.df_out_csv, args.out)
        else:
            LOG.warning("Nothing to draw")
        return None

    def _walk_rows(self, start_path):
        if self.inverse_regex:
            df = df_regex_filter(self.df, cols.SRC_PATH, self.inverse_regex)
            start_paths = df[cols.SRC_PATH].tolist() if not df.empty else []
            for inverse_path in dict.fromkeys(start_paths):
                LOG.debug("Start path inverse: %s", inverse_path)
            return walk_dependency_rows(
                self.df,
                start_paths,
                self.maxdepth,
                inverse=True,
                stop_at=self._matches_until,
            )
        LOG.debug("Start path: %s", start_path)
        return walk_dependency_rows(
            self.df,
            start_path,
            self.maxdepth,
            stop_at=self._matches_until,
        )

    def _walked_rows_to_dataframe(self, walked_rows):
        rows = [{"graph_depth": walked.depth, **walked.row} for walked in walked_rows]
        if rows:
            return pd.DataFrame.from_records(rows)
        return pd.DataFrame()

    def _draw_row(self, row, depth):
        self._dbg_print_row(row, depth)
        if self._matches_until(row):
            LOG.debug("%sReached until_function", (DBG_INDENT * (depth - 1)))
            return
        self._add_node(row[cols.SRC_PATH], row["src_pname"])
        self._add_node(row[cols.TARGET_PATH], row["target_pname"])
        self._add_edge(row)

    def _init_df_out(self, args):
        if hasattr(args, "out"):
            _fname, extension = os.path.splitext(args.out)
            fileformat = extension[1:]
            if fileformat == "csv":
                self.df_out_csv = pd.DataFrame()
        elif hasattr(args, "return_df") and args.return_df:
            self.df_out_csv = pd.DataFrame()
        else:
            self.df_out_csv = None

    def _render(self, filename):
        if self.df_out_csv is not None:
            return
        if self.digraph is None:
            return
        fname, extension = os.path.splitext(filename)
        gformat = extension[1:]
        self.digraph.render(filename=fname, format=gformat, cleanup=True)
        LOG.info("Wrote: %s", filename)

    def _matches_until(self, row):
        return regex_match(self.until_regex, row["target_pname"])

    def _add_edge(self, row):
        if self.df_out_csv is not None:
            return
        if self.digraph is None:
            return
        self.digraph.edge(row[cols.TARGET_PATH], row[cols.SRC_PATH], style=None)

    def _add_node(self, path, pname):
        if self.df_out_csv is not None:
            return
        if self.digraph is None:
            return
        node_id = path
        node_name = html.escape(str(pname))
        if self.pathnames:
            beg = '<FONT POINT-SIZE="8">'
            end = "</FONT>"
            label = f"<{node_name}<BR/>{beg}{str(path)}{end}>"
        else:
            label = node_name
        fillcolor = "#EEEEEE"
        if regex_match(self.colorize_regex, pname):
            fillcolor = "#FFE6E6"
        self.digraph.node(node_id, label, style="rounded,filled", fillcolor=fillcolor)

    def _dbg_print_row(self, row: dict[str, Any], depth):
        LOG.log(
            LOG_SPAM,
            "%sFound: %s ==> %s",
            (DBG_INDENT * (depth - 1)),
            row[cols.TARGET_PATH],
            row[cols.SRC_PATH],
        )
