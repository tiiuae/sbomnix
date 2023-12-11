#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

""" Python script that generates SBOMs from nix packages """

import argparse
import pathlib
from sbomnix.sbomdb import SbomDb
from common.utils import (
    LOG,
    set_log_verbosity,
    check_positive,
    get_py_pkg_version,
    exit_unless_nix_artifact,
)

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
    helps = "Scan buildtime dependencies instead of runtime dependencies"
    parser.add_argument("--buildtime", help=helps, action="store_true")
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
    set_log_verbosity(args.verbose)
    target_path = args.NIX_PATH.resolve().as_posix()
    runtime = args.buildtime is False
    exit_unless_nix_artifact(target_path, force_realise=runtime)
    if not args.meta:
        LOG.warning(
            "Command line argument '--meta' missing: SBOM will not include "
            "license information (see '--help' for more details)"
        )
    sbomdb = SbomDb(target_path, args.buildtime, args.meta, args.depth)
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
