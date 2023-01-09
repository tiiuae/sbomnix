#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-few-public-methods, invalid-name
# pylint: disable=too-many-instance-attributes

""" Python script to query and visualize nix package dependencies """

import os
import re
import logging
import html
from dataclasses import dataclass
import pandas as pd
import graphviz as gv

from sbomnix.utils import (
    LOGGER_NAME,
    LOG_SPAM,
    exec_cmd,
    df_to_csv_file,
    regex_match,
    df_regex_filter,
)

###############################################################################

_LOG = logging.getLogger(LOGGER_NAME)

###############################################################################


class NixGraphFilter:
    """Filter graph entries based on specified arguments"""

    def __init__(self, src_path=None, target_path=None):
        self.src_path = src_path
        self.target_path = target_path

    def get_query_str(self):
        """Return filter representation as string"""
        return " and ".join(
            [
                f"{key} == '{value}'"
                for key, value in self.__dict__.items()
                if value is not None
            ]
        )


###############################################################################

DBG_INDENT = "    "


class NixDependencyGraph:
    """Draw nix package dependencies as graph"""

    def __init__(self, df_dependencies):
        self.df = df_dependencies
        self.digraph = None
        # Keep track of paths drawn to not re-draw them
        self.paths_drawn = set()
        # Rows that match the query when output format is csv
        self.df_out_csv = None
        # Default parameters
        self.maxdepth = 1
        self.inverse_regex = None
        self.until_regex = None
        self.colorize_regex = None

    def draw(self, start_path, args):
        """Draw dependency graph"""
        self._is_csv_out(args.out)
        self.maxdepth = args.depth
        self.inverse_regex = args.inverse
        self.until_regex = args.until
        self.colorize_regex = args.colorize
        self.digraph = gv.Digraph(filename=args.out)
        self.digraph.attr("graph", rankdir="LR")
        self.digraph.attr("node", shape="box")
        self.digraph.attr("node", style="rounded")
        self.digraph.attr("node", margin="0.3,0.1")
        self.digraph.attr("graph", concentrate="false")
        initlen = len(self.digraph.body)

        if self.inverse_regex:
            # If inverse_regex is specified, draw the graph backwards starting
            # from nodes where src_pname matches the specified regex
            df = df_regex_filter(self.df, "src_pname", self.inverse_regex)
            for row in df.itertuples():
                inverse_path = row.src_path
                _LOG.debug("Start path inverse: %s", inverse_path)
                nixfilter = NixGraphFilter(src_path=inverse_path)
                self._graph(nixfilter)
        else:
            # Otherwise, draw the graph starting from the given start_path
            _LOG.debug("Start path: %s", start_path)
            nixfilter = NixGraphFilter(target_path=start_path)
            self._graph(nixfilter)

        if len(self.digraph.body) > initlen:
            # Render the graph if any nodes were added
            self._render(args.out)
        elif self.df_out_csv is not None and not self.df_out_csv.empty:
            # Output csv if csv format was specified
            df_to_csv_file(self.df_out_csv, args.out)
        else:
            _LOG.warning("No matches: nothing to draw")

    def _is_csv_out(self, filename):
        _fname, extension = os.path.splitext(filename)
        fileformat = extension[1:]
        if fileformat == "csv":
            self.df_out_csv = pd.DataFrame()
        else:
            self.df_out_csv = None

    def _render(self, filename):
        if self.df_out_csv is not None:
            return
        fname, extension = os.path.splitext(filename)
        gformat = extension[1:]
        self.digraph.render(filename=fname, format=gformat, cleanup=True)
        _LOG.info("Wrote: %s", filename)

    def _graph(self, nixfilter, curr_depth=0):
        curr_depth += 1
        if curr_depth > self.maxdepth:
            _LOG.log(LOG_SPAM, "Reached maxdepth: %s", self.maxdepth)
            return
        df = self._query(nixfilter, curr_depth)
        if df.empty and curr_depth == 1:
            # First match failed: print to console and stop
            _LOG.info("No matching packages found")
            return
        if df.empty:
            # Reached leaf: no more matches
            _LOG.debug("%sFound nothing", (DBG_INDENT * (curr_depth - 1)))
            return
        if self.df_out_csv is not None:
            df.insert(0, "graph_depth", curr_depth)
            self.df_out_csv = pd.concat([self.df_out_csv, df])
        for row in df.itertuples():
            self._dbg_print_row(row, curr_depth)
            # Stop drawing if 'until_regex' matches
            if regex_match(self.until_regex, row.target_pname):
                _LOG.debug("%sReached until_function", (DBG_INDENT * (curr_depth - 1)))
                continue
            if self._path_drawn(row):
                _LOG.debug("%sSkipping duplicate path", (DBG_INDENT * (curr_depth - 1)))
                continue
            # Add source node
            self._add_node(row.src_path, row.src_pname)
            # Add target node
            self._add_node(row.target_path, row.target_pname)
            # Add edge between the nodes
            self._add_edge(row)

            # Construct the filter for next query in the graph
            if self.inverse_regex:
                nixfilter = NixGraphFilter(src_path=row.target_path)
            else:
                nixfilter = NixGraphFilter(target_path=row.src_path)

            # Recursively find the next entries
            self._graph(nixfilter, curr_depth)

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
        _LOG.debug("%sFiltering by: %s", (DBG_INDENT * (depth - 1)), query_str)
        return self.df.query(query_str)

    def _add_edge(self, row):
        if self.df_out_csv is not None:
            return
        self.digraph.edge(row.target_path, row.src_path, style=None)

    def _add_node(self, path, pname):
        if self.df_out_csv is not None:
            return
        node_id = path
        label = html.escape(str(pname))
        fillcolor = "#EEEEEE"
        if regex_match(self.colorize_regex, pname):
            fillcolor = "#FFE6E6"
        # Add node to the graph
        self.digraph.node(node_id, label, style="rounded,filled", fillcolor=fillcolor)

    def _dbg_print_row(self, row, depth):
        _LOG.log(
            LOG_SPAM,
            "%sFound: %s ==> %s",
            (DBG_INDENT * (depth - 1)),
            row.target_path,
            row.src_path,
        )


###############################################################################


@dataclass(eq=False)
class NixDependency:
    """Represents dependency between two nix packages"""

    src_path: str
    src_pname: str
    target_path: str
    target_pname: str

    def to_dict(self):
        """Return as dictionary"""
        ret = {}
        for attr in vars(self):
            ret[attr] = getattr(self, attr)
        return ret


class NixDependencies:
    """Parse nix package dependencies"""

    def __init__(self, nix_path, buildtime=False):
        _LOG.debug("nix_path: %s", nix_path)
        self.dependencies = set()
        self.start_path = ""
        self.dtype = "buildtime" if buildtime else "runtime"
        _LOG.info("Loading %s dependencies referenced by '%s'", self.dtype, nix_path)
        if buildtime:
            self._parse_buildtime_dependencies(nix_path)
        else:
            self._parse_runtime_dependencies(nix_path)

    def _parse_runtime_dependencies(self, nix_path):
        # map nix_path to output path by calling nix path-info
        nix_out = exec_cmd(
            [
                "nix",
                "--extra-experimental-features",
                "nix-command",
                "path-info",
                nix_path,
            ]
        ).strip()
        _LOG.debug("nix_out: %s", nix_out)
        self.start_path = nix_out
        # nix-store -q --graph outputs runtime dependencies when applied
        # to output path
        nix_query_out = exec_cmd(["nix-store", "-q", "--graph", nix_out])
        _LOG.log(LOG_SPAM, "nix_query_out: %s", nix_query_out)
        self._parse_nix_query_out(nix_query_out)

    def _parse_buildtime_dependencies(self, nix_path):
        # map nix_path to derivation path by calling nix path-info
        nix_drv = exec_cmd(
            [
                "nix",
                "--extra-experimental-features",
                "nix-command",
                "path-info",
                "--derivation",
                nix_path,
            ]
        ).strip()
        _LOG.debug("nix_drv: %s", nix_drv)
        self.start_path = nix_drv
        # nix-store -q --graph outputs buildtime dependencies when applied
        # to derivation path
        nix_query_out = exec_cmd(["nix-store", "-q", "--graph", nix_drv])
        _LOG.log(LOG_SPAM, "nix_query_out: %s", nix_query_out)
        self._parse_nix_query_out(nix_query_out)

    def _parse_nix_query_out(self, nix_query_out):
        # Match lines like:
        #  "3sjd4vvb-bash-5.1" -> "qcvlk255-hello-2.12.1" ...
        re_dependency = re.compile(
            r"^\"(?P<src_hash>[^-]+)-(?P<src_pname>.*?)"
            r"\" -> \""
            r"(?P<target_hash>[^-]+)-(?P<target_pname>.*?)\""
        )
        for line in nix_query_out.splitlines():
            dep_match = re_dependency.match(line)
            if dep_match:
                self._add_dependency(dep_match)

    def _add_dependency(self, dep_match):
        src_pname = dep_match.group("src_pname")
        src_hash = dep_match.group("src_hash")
        src_path = f"/nix/store/{src_hash}-{src_pname}"
        target_pname = dep_match.group("target_pname")
        target_hash = dep_match.group("target_hash")
        target_path = f"/nix/store/{target_hash}-{target_pname}"
        edge = NixDependency(src_path, src_pname, target_path, target_pname)
        self.dependencies.add(edge)

    def to_dataframe(self):
        """Return the dependencies as pandas dataframe"""
        deps = [dep.to_dict() for dep in self.dependencies]
        df = pd.DataFrame.from_records(deps)
        if _LOG.level <= logging.DEBUG:
            df_to_csv_file(df, f"nixgraph_deps_{self.dtype}.csv")
        return df

    def graph(self, args):
        """Draw the dependencies as directed graph"""
        digraph = NixDependencyGraph(self.to_dataframe())
        digraph.draw(self.start_path, args)


################################################################################
