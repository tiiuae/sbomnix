#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

""" Python script to query and visualize nix package dependencies """

import argparse
import logging
import pathlib
import sys
from nixgraph.graph import NixDependencies
from sbomnix.utils import setup_logging, get_version, LOGGER_NAME

###############################################################################

_LOG = logging.getLogger(LOGGER_NAME)

###############################################################################


def check_positive(val):
    """Raise ArgumentTypeError if val is not a positive integer"""
    intval = int(val)
    if intval <= 0:
        raise argparse.ArgumentTypeError(f"{val} is not a positive integer")
    return intval


def getargs():
    """Parse command line arguments"""
    desc = "Visualize nix artifact dependencies"
    epil = "Example: nixgraph /path/to/derivation.drv "
    parser = argparse.ArgumentParser(description=desc, epilog=epil)

    helps = "Path to nix artifact, e.g.: derivation file or nix output path"
    parser.add_argument("NIX_PATH", help=helps, type=pathlib.Path)
    parser.add_argument("--version", action="version", version=get_version())

    helps = "Scan buildtime dependencies instead of runtime dependencies"
    parser.add_argument("--buildtime", help=helps, action="store_true")

    helps = "Set the graph maxdepth (default: --depth=1)"
    parser.add_argument("--depth", help=helps, type=check_positive, default=1)

    helps = (
        "Draw inverse graph starting from nodes that match the specified "
        "regular expression"
    )
    parser.add_argument("--inverse", help=helps)

    helps = (
        "Set the output file name, default is 'graph.png'. "
        "The output filename extension determines the output format. "
        "Common supported formats include: png, jpg, pdf, and dot. "
        "For a full list of supported output formats, see: "
        "https://graphviz.org/doc/info/output.html. In addition to graphviz "
        "supported output formats, the tool supports output in csv to "
        "allow post-processing the output data. Specify output file with "
        ".csv extension to output the query result in textual csv format."
    )
    parser.add_argument("--out", nargs="?", help=helps, default="graph.png")

    helps = "Colorize nodes that match the specified regular expression"
    parser.add_argument("--colorize", help=helps)

    helps = (
        "Keep drawing the dependencies until package name matches "
        "the specified regular expression. This option works together with "
        "--depth so that drawing stops when the first of the two "
        "conditions match: when the package name matches the given regex "
        "or when the specified graph depth is reached."
    )
    parser.add_argument("--until", help=helps)

    helps = "Show nix store path in node label, together with package name"
    parser.add_argument("--pathnames", help=helps, action="store_true")

    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)

    return parser.parse_args()


################################################################################


def main():
    """main entry point"""
    args = getargs()
    setup_logging(args.verbose)
    if not args.NIX_PATH.exists():
        _LOG.fatal("Invalid path: '%s'", args.NIX_PATH)
        sys.exit(1)
    target_path = args.NIX_PATH.resolve().as_posix()
    deps = NixDependencies(target_path, args.buildtime)
    deps.graph(args)


if __name__ == "__main__":
    main()

################################################################################
