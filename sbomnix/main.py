#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

""" Python script that generates SBOMs from nix packages """

import argparse
import logging
from sbomnix.sbomdb import SbomDb
from sbomnix.utils import (
    setup_logging,
    get_version,
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
    epil = (
        "Example: sbomnix /path/to/derivation.drv --meta /path/to/meta.json --runtime"
    )
    parser = argparse.ArgumentParser(description=desc, epilog=epil)

    helps = "Path to nix artifact, e.g.: derivation file or nix output path"
    parser.add_argument("NIX_PATH", nargs=1, help=helps)
    parser.add_argument("--version", action="version", version=get_version())

    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)

    helps = (
        "Path to json file that details meta information. "
        "Generate this file with: `nix-env -qa --meta --json '.*' >meta.json` "
        "then give the path to generated json file to this script via the "
        "--meta argument to include the license and maintainer information "
        "to the output of this script (default: None)"
    )
    parser.add_argument("--meta", nargs="?", help=helps, default=None)

    helps = "Set the type of dependencies included to the SBOM (default: runtime)"
    types = ["runtime", "buildtime", "both"]
    parser.add_argument("--type", choices=types, help=helps, default="runtime")

    group = parser.add_argument_group("output arguments")
    helps = "Path to csv output file (default: ./sbom.csv)"
    group.add_argument("--csv", nargs="?", help=helps, default="sbom.csv")
    helps = "Path to cyclonedx output file (default: ./sbom.cdx.json)"
    group.add_argument("--cdx", nargs="?", help=helps, default="sbom.cdx.json")

    return parser.parse_args()


################################################################################


def main():
    """main entry point"""
    args = getargs()
    setup_logging(args.verbose)
    target_path = args.NIX_PATH[0]
    if not args.meta:
        _LOG.warning(
            "Command line argument '--meta' missing: SBOM will not include "
            "license information (see '--help' for more details)"
        )
    runtime = args.type in ("runtime", "both")
    buildtime = args.type in ("buildtime", "both")

    sbomdb = SbomDb(target_path, runtime, buildtime, args.meta)
    if args.cdx:
        sbomdb.to_cdx(args.cdx)
    if args.csv:
        sbomdb.to_csv(args.csv)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
