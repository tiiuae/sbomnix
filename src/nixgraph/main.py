#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Python script to query and visualize nix package dependencies"""

import argparse

from common.cli_args import add_verbose_argument, add_version_argument, check_positive
from common.errors import SbomnixError
from common.log import LOG, set_log_verbosity
from nixgraph.graph import NixDependencies
from sbomnix.cli_utils import resolve_nix_target

###############################################################################


def getargs(args=None):
    """Parse command line arguments"""
    desc = "Visualize nix artifact dependencies"
    epil = "Example: nixgraph /path/to/derivation.drv "
    parser = argparse.ArgumentParser(description=desc, epilog=epil)

    helps = (
        "Target nix store path (e.g. derivation file or nix output path) or flakeref"
    )
    parser.add_argument("NIXREF", help=helps, type=str)

    add_version_argument(parser)

    helps = "Scan buildtime dependencies instead of runtime dependencies"
    parser.add_argument("--buildtime", help=helps, action="store_true")

    helps = "Set the graph maxdepth (default: --depth=1)"
    parser.add_argument("--depth", help=helps, type=check_positive, default=1)

    helps = (
        "Draw inverse graph starting from node (path) names that match the "
        "specified regular expression"
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
    parser.add_argument("-o", "--out", nargs="?", help=helps, default="graph.png")

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

    add_verbose_argument(parser)

    return parser.parse_args(args)


################################################################################


def main():
    """main entry point"""
    args = getargs()
    set_log_verbosity(args.verbose)
    try:
        _run(args)
    except SbomnixError as error:
        LOG.fatal("%s", error)
        raise SystemExit(1) from error


def _run(args):
    target = resolve_nix_target(args.NIXREF, buildtime=args.buildtime)
    deps = NixDependencies(target.path, args.buildtime)
    deps.graph(args)


if __name__ == "__main__":
    main()

################################################################################
