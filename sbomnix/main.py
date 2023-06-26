#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

""" Python script that generates SBOMs from nix packages """

import argparse
import logging
import pathlib
import sys
from sbomnix.sbomdb import SbomDb
from sbomnix.utils import (
    check_positive,
    setup_logging,
    get_py_pkg_version,
    LOGGER_NAME,
)

###############################################################################

_LOG = logging.getLogger(LOGGER_NAME)

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = (
        "This tool finds dependencies of the specified nix artifact "
        "in NIX_PATH and "
        "writes SBOM file(s) as specified in output arguments."
    )
    epil = "Example: sbomnix /path/to/nix/out --meta /path/to/meta.json"
    parser = argparse.ArgumentParser(description=desc, epilog=epil)

    helps = "Path to nix artifact, e.g.: derivation file or nix output path"
    parser.add_argument("NIX_PATH", help=helps, type=pathlib.Path)
    helps = (
        "Path to json file that details meta information. "
        "Generate this file with: `nix-env -qa --meta --json '.*' >meta.json` "
        "then give the path to generated json file to this script via the "
        "--meta argument to include the license and maintainer information "
        "to the output of this script (default: None)"
    )
    parser.add_argument("--meta", nargs="?", help=helps, default=None)
    helps = (
        "Set the type of dependencies included to the SBOM (default: runtime). "
        "Note: generating 'runtime' SBOM requires realising (building) the "
        "output paths of the target derivation. When 'runtime' SBOM is "
        "requested, sbomnix will realise the target derivation unless its already "
        "realised. See `nix-store --realise --help` for more info."
    )
    types = ["runtime", "buildtime", "both"]
    parser.add_argument("--type", choices=types, help=helps, default="runtime")
    helps = (
        "Set the depth of the included dependencies. As an example, --depth=1 "
        "indicates the SBOM should include only the NIX_PATH direct dependencies. "
        "With --depth=2, the output SBOM includes the direct dependencies and the "
        "first level of transitive dependencies. "
        "By default, when --depth is not specified, the output SBOM includes "
        "all dependencies all the way to the root of the dependency tree."
    )
    parser.add_argument("--depth", help=helps, type=check_positive)
    parser.add_argument("--version", action="version", version=get_py_pkg_version())
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)

    group = parser.add_argument_group("output arguments")
    helps = "Path to csv output file (default: ./sbom.csv)"
    group.add_argument("--csv", nargs="?", help=helps, default="sbom.csv")
    helps = "Path to cyclonedx json output file (default: ./sbom.cdx.json)"
    group.add_argument("--cdx", nargs="?", help=helps, default="sbom.cdx.json")
    helps = "Path to spdx json output file (default: ./sbom.spdx.json)"
    group.add_argument("--spdx", nargs="?", help=helps, default="sbom.spdx.json")

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
    if not args.meta:
        _LOG.warning(
            "Command line argument '--meta' missing: SBOM will not include "
            "license information (see '--help' for more details)"
        )
    runtime = args.type in ("runtime", "both")
    buildtime = args.type in ("buildtime", "both")

    sbomdb = SbomDb(target_path, runtime, buildtime, args.meta, args.depth)
    if args.cdx:
        sbomdb.to_cdx(args.cdx)
    if args.spdx:
        sbomdb.to_spdx(args.spdx)
    if args.csv:
        sbomdb.to_csv(args.csv)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
