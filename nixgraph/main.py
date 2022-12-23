#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

""" Python script to query and visualize nix package dependencies """

import os
import argparse
from nixgraph.graph import NixDependencies
from sbomnix.utils import setup_logging

###############################################################################


def check_positive(val):
    """Raise ArgumentTypeError if val is not a positive integer"""
    intval = int(val)
    if intval <= 0:
        raise argparse.ArgumentTypeError(f"{val} is not a positive integer")
    return intval


def getargs():
    """Parse command line arguments"""
    desc = "Visualize nix package dependencies"
    epil = f"Example: ./{os.path.basename(__file__)} /path/to/derivation.drv "
    parser = argparse.ArgumentParser(description=desc, epilog=epil)

    helps = "Path to nix artifact, e.g.: derivation file or nix output path"
    parser.add_argument("NIX_PATH", nargs=1, help=helps)

    helps = "Scan buildtime dependencies instead of runtime dependencies"
    parser.add_argument("--buildtime", help=helps, action="store_true")

    helps = "Set the graph maxdepth (default: --depth=1)"
    parser.add_argument("--depth", help=helps, type=check_positive, default=1)

    helps = (
        "Set the output file name, default is 'graph.png'. "
        "The output filename extension determines the output format. "
        "Common supported formats include: png, jpg, pdf, and dot. "
        "For a full list of supported output formats, see: "
        "https://graphviz.org/doc/info/output.html."
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

    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)

    return parser.parse_args()


################################################################################


def main():
    """main entry point"""
    args = getargs()
    setup_logging(args.verbose)
    target_path = args.NIX_PATH[0]
    deps = NixDependencies(target_path, args.buildtime)
    deps.graph(args)


if __name__ == "__main__":
    main()

################################################################################
