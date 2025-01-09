#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-locals

"""Python script that compares dependencies between sbomnix and nixgraph"""

import argparse
import json
import logging
import os
import pathlib
import sys

import pandas as pd

from common.utils import (
    LOG,
    LOG_SPAM,
    df_from_csv_file,
    df_to_csv_file,
    regex_match,
    set_log_verbosity,
)

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = "Compare nixgraph and sbomnix output to cross-validate"
    epil = (
        f"Example: ./{os.path.basename(__file__)} "
        "--sbom /path/to/sbom.json --graph /path/to/graph.csv"
    )
    parser = argparse.ArgumentParser(description=desc, epilog=epil)
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)
    helps = "Path to sbom in csv format"
    parser.add_argument("--sbom", help=helps, type=pathlib.Path, required=True)
    helps = "Path to graph in csv format"
    parser.add_argument("--graph", help=helps, type=pathlib.Path, required=True)
    return parser.parse_args()


################################################################################


def _parse_sbom(path):
    LOG.info("Loading sbom data from '%s'", path)
    with path.open(encoding="utf-8") as inf:
        json_dict = json.loads(inf.read())

        # Parse sbom type
        sbom_type = ""
        for prop_dict in json_dict["metadata"]["properties"]:
            if "sbom_type" in prop_dict["name"]:
                sbom_type = prop_dict["value"]
        if not sbom_type:
            LOG.fatal("Failed to find sbom_type")
            sys.exit(1)
        LOG.debug(sbom_type)

        # Parse components
        components = json_dict["components"] + [json_dict["metadata"]["component"]]
        comp_parsed_dict = {}
        setcol = comp_parsed_dict.setdefault
        for cmp in components:
            # setcol("bom_ref", []).append(cmp["bom-ref"])
            outpaths = []
            for prop_dict in cmp["properties"]:
                if "output_path" in prop_dict["name"]:
                    outpaths.append(prop_dict["value"])
                elif "drv_path" in prop_dict["name"]:
                    setcol("drv_path", []).append(prop_dict["value"])
            setcol("output_path", []).append(outpaths)
        df_components = pd.DataFrame(comp_parsed_dict)

        # Parse dependencies
        deps = json_dict["dependencies"]
        deps_parsed_dict = {}
        setcol = deps_parsed_dict.setdefault
        for dep in deps:
            if "dependsOn" not in dep:
                setcol("ref", []).append(dep["ref"])
                setcol("depends_on", []).append("")
                continue
            for dependson in dep["dependsOn"]:
                setcol("ref", []).append(dep["ref"])
                setcol("depends_on", []).append(dependson)
        df_dependencies = pd.DataFrame(deps_parsed_dict)

        # Join df_components with df_dependencies
        df_parsed = df_components.merge(
            df_dependencies,
            how="outer",
            left_on=["drv_path"],
            right_on=["ref"],
        )
        df_parsed.fillna("", inplace=True)
        if LOG.level <= logging.DEBUG:
            df_to_csv_file(df_parsed, "df_sbom_parsed.csv")
        return df_parsed, sbom_type


def _parse_graph(path):
    LOG.info("Loading graph data from '%s'", path)
    df_graph = df_from_csv_file(path)
    df_graph.fillna("", inplace=True)
    df_graph = df_graph.astype(str)
    src_path = df_graph["src_path"].iloc[0]
    graph_type = "buildtime" if regex_match(r".*\.[a-z]+$", src_path) else "runtime"
    return df_graph, graph_type


def _filter_set(re_filter_out_list, target_set):
    matching_set = set()
    for target in target_set:
        for regex in re_filter_out_list:
            if regex_match(regex, target):
                matching_set.add(target)
                break
    return target_set - matching_set


################################################################################


def sbom_internal_checks(df_sbom):
    """Cross-check sbom components vs dependencies"""
    passed = True
    # Empty "output_path" indicates component is referenced in the
    # sbom "dependency" section, but missing from the "components" section
    df = df_sbom[df_sbom["output_path"].isna()]
    if not df.empty:
        missing = df["ref"].to_list()
        LOG.fatal("sbom component missing: %s", missing)
        passed = False
    # Empty "ref" indicates component is listed in the sbom
    # "components" section, but missing from the "dependencies"
    df = df_sbom[df_sbom["ref"].isna()]
    if not df.empty:
        missing = df["drv_path"].to_list()
        LOG.fatal("sbom dependency missing for component: %s", missing)
        passed = False
    return passed


def compare_dependencies(df_sbom, df_graph, sbom_type, graph_type):
    """Compare dependencies in df_sbom and df_braph"""
    LOG.debug("sbom_type=%s", sbom_type)
    LOG.debug("graph_type=%s", graph_type)
    deps_only_in_sbom = set()
    deps_only_in_graph = set()
    df_sbom = df_sbom.explode("output_path")
    df_sbom = df_sbom.astype(str)

    if (graph_type == "runtime" and sbom_type != "runtime_only") or (
        graph_type == "buildtime" and sbom_type == "runtime_only"
    ):
        LOG.fatal("Unable to compare: graph='%s' vs sbom='%s'", graph_type, sbom_type)
        return False
    if graph_type == "runtime":
        LOG.info("Comparing runtime dependencies")
        for out_path in df_sbom["output_path"].unique().tolist():
            LOG.log(LOG_SPAM, "target: %s", out_path)
            df_sbom_deps = df_sbom[df_sbom["output_path"] == out_path]
            sbom_deps = list(filter(None, df_sbom_deps["depends_on"].unique().tolist()))
            LOG.log(LOG_SPAM, "sbom    depends-ons: %s", sbom_deps)
            df_graph_deps = df_graph[df_graph["target_path"] == out_path]
            # Map graph src_path to sbom paths
            dfr = df_sbom.merge(
                df_graph_deps, how="inner", left_on="output_path", right_on="src_path"
            ).loc[:, ["drv_path"]]
            graph_deps = list(filter(None, dfr["drv_path"].unique().tolist()))
            LOG.log(LOG_SPAM, "graph   depends-ons: %s", graph_deps)
            deps_only_in_sbom.update(set(sbom_deps) - set(graph_deps))
            deps_only_in_graph.update(set(graph_deps) - set(sbom_deps))

    if graph_type == "buildtime":
        LOG.info("Comparing buildtime dependencies")
        for drv_path in df_sbom["drv_path"].unique().tolist():
            LOG.log(LOG_SPAM, "target: %s", drv_path)
            df_sbom_deps = df_sbom[df_sbom["drv_path"] == drv_path]
            sbom_deps = list(filter(None, df_sbom_deps["depends_on"].unique().tolist()))
            LOG.log(LOG_SPAM, "sbom    depends-ons: %s", sbom_deps)
            dfr = df_graph[df_graph["target_path"] == drv_path]
            graph_deps = list(filter(None, dfr["src_path"].unique().tolist()))
            LOG.log(LOG_SPAM, "graph   depends-ons: %s", graph_deps)
            deps_only_in_sbom.update(set(sbom_deps) - set(graph_deps))
            deps_only_in_graph.update(set(graph_deps) - set(sbom_deps))

    # Filter out the following dependencies from the "deps_only_in_graph":
    # Store paths that match these regular expressions have no known derivers.
    # As such, they are not included in the sbom, but they are still drawn in
    # the graph. Not including such paths in the sbom is not an error, so
    # we filter them out here:
    re_no_known_drvs = [
        r".*\.patch$",
        r".*\.patch.gz$",
        r".*\.sh$",
        r".*\.bash$",
        r".*\.diff$",
        r".*\.c$",
        r".*\.h$",
        r".*\.py$",
        r".*\.pl$",
        r".*\.xsl$",
        r".*\.lock$",
        r".*\.cnf$",
        r".*\.conf$",
        r".*\.crt$",
        r".*\.nix$",
        r".*\.toml$",
        r".*\.tmac$",
        r".*\.ds$",
        r".*\.key$",
        r".*\-source$",
        r".*\-builder$",
        r".*\-prefetch-git$",
        r".*\-inputrc$",
        r".*\-patch-registry-deps$",
        r".*\-make-initrd-ng$",
    ]
    deps_only_in_graph = _filter_set(re_no_known_drvs, deps_only_in_graph)

    passed = True
    if deps_only_in_sbom:
        passed = False
        LOG.fatal("Dependencies only in sbom:")
        for dep in sorted(deps_only_in_sbom):
            LOG.fatal("  %s", dep)

    if deps_only_in_graph:
        passed = False
        LOG.fatal("Dependencies only in graph:")
        for dep in sorted(deps_only_in_graph):
            LOG.fatal("  %s", dep)

    return passed


################################################################################


def main():
    """main entry point"""
    args = getargs()
    set_log_verbosity(args.verbose)
    if not args.sbom.exists():
        LOG.fatal("Invalid path: '%s'", args.sbom)
        sys.exit(1)
    if not args.graph.exists():
        LOG.fatal("Invalid path: '%s'", args.graph)
        sys.exit(1)
    df_sbom, sbom_type = _parse_sbom(args.sbom)
    df_graph, graph_type = _parse_graph(args.graph)

    # Checks
    sbom_check = sbom_internal_checks(df_sbom)
    deps_check = compare_dependencies(df_sbom, df_graph, sbom_type, graph_type)

    if sbom_check and deps_check:
        sys.exit(0)
    else:
        sys.exit(1)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
