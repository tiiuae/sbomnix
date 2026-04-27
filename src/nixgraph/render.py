#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-few-public-methods
# pylint: disable=too-many-instance-attributes

"""Helpers for traversing and rendering nix dependency graphs."""

import html
import os

import graphviz as gv
import pandas as pd

from common.df import df_regex_filter, df_to_csv_file
from common.log import LOG, LOG_SPAM
from common.regex import regex_match

DBG_INDENT = "    "


class NixGraphFilter:
    """Filter graph entries based on specified arguments."""

    def __init__(self, src_path=None, target_path=None):
        self.src_path = src_path
        self.target_path = target_path

    def get_query_str(self):
        """Return filter representation as string."""
        return " and ".join(
            [
                f"{key} == '{value}'"
                for key, value in self.__dict__.items()
                if value is not None
            ]
        )


class NixDependencyGraph:
    """Draw nix package dependencies as graph."""

    def __init__(self, df_dependencies):
        self.df = df_dependencies
        self.digraph = None
        self.paths_drawn = set()
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

        if self.inverse_regex:
            df = df_regex_filter(self.df, "src_path", self.inverse_regex)
            for row in df.itertuples():
                inverse_path = row.src_path
                LOG.debug("Start path inverse: %s", inverse_path)
                self._graph(NixGraphFilter(src_path=inverse_path))
        else:
            LOG.debug("Start path: %s", start_path)
            self._graph(NixGraphFilter(target_path=start_path))

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
        fname, extension = os.path.splitext(filename)
        gformat = extension[1:]
        self.digraph.render(filename=fname, format=gformat, cleanup=True)
        LOG.info("Wrote: %s", filename)

    def _graph(self, nixfilter, curr_depth=0):
        curr_depth += 1
        if curr_depth > self.maxdepth:
            LOG.log(LOG_SPAM, "Reached maxdepth: %s", self.maxdepth)
            return
        df = self._query(nixfilter, curr_depth)
        if df.empty and curr_depth == 1:
            LOG.debug("No matching packages found")
            return
        if df.empty:
            LOG.debug("%sFound nothing", (DBG_INDENT * (curr_depth - 1)))
            return
        if self.df_out_csv is not None:
            df.insert(0, "graph_depth", curr_depth)
            self.df_out_csv = pd.concat([self.df_out_csv, df])
        for row in df.itertuples():
            self._dbg_print_row(row, curr_depth)
            if regex_match(self.until_regex, row.target_pname):
                LOG.debug("%sReached until_function", (DBG_INDENT * (curr_depth - 1)))
                continue
            if self._path_drawn(row):
                LOG.debug("%sSkipping duplicate path", (DBG_INDENT * (curr_depth - 1)))
                continue
            self._add_node(row.src_path, row.src_pname)
            self._add_node(row.target_path, row.target_pname)
            self._add_edge(row)

            if self.inverse_regex:
                next_filter = NixGraphFilter(src_path=row.target_path)
            else:
                next_filter = NixGraphFilter(target_path=row.src_path)
            self._graph(next_filter, curr_depth)

    def _path_drawn(self, row):
        if row is None:
            return False
        hash_str = hash(f"{row.target_path}:{row.src_path}")
        if hash_str in self.paths_drawn:
            return True
        self.paths_drawn.add(hash_str)
        return False

    def _query(self, nixfilter, depth):
        query_str = nixfilter.get_query_str()
        LOG.debug("%sFiltering by: %s", (DBG_INDENT * (depth - 1)), query_str)
        if self.df.empty:
            return pd.DataFrame()
        return self.df.query(query_str)

    def _add_edge(self, row):
        if self.df_out_csv is not None:
            return
        self.digraph.edge(row.target_path, row.src_path, style=None)

    def _add_node(self, path, pname):
        if self.df_out_csv is not None:
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

    def _dbg_print_row(self, row, depth):
        LOG.log(
            LOG_SPAM,
            "%sFound: %s ==> %s",
            (DBG_INDENT * (depth - 1)),
            row.target_path,
            row.src_path,
        )
