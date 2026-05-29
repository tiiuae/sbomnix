#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Python script that generates SBOMs from nix packages"""

import argparse
import time

from common.cli_args import add_verbose_argument, add_version_argument, check_positive
from common.errors import SbomnixError
from common.log import LOG, set_log_verbosity
from sbomnix.builder import SbomBuilder
from sbomnix.cli_utils import resolve_nix_target

###############################################################################


def getargs(args=None):
    """Parse command line arguments"""
    desc = (
        "This tool finds dependencies of the specified nix store path "
        "or flake reference NIXREF and "
        "writes SBOM file(s) as specified in output arguments."
    )
    epil = "Example: sbomnix /nix/store/path/or/flakeref"
    parser = argparse.ArgumentParser(description=desc, epilog=epil)

    helps = (
        "Target nix store path (e.g. derivation file or nix output path) or flakeref"
    )
    parser.add_argument("NIXREF", help=helps, type=str)
    helps = "Scan buildtime dependencies instead of runtime dependencies"
    parser.add_argument("--buildtime", help=helps, action="store_true")
    helps = (
        "Set the depth of the included dependencies. As an example, --depth=1 "
        "indicates the SBOM should include only the NIXREF direct dependencies. "
        "With --depth=2, the output SBOM includes the direct dependencies and the "
        "first level of transitive dependencies. "
        "By default, when --depth is not specified, the output SBOM includes "
        "all dependencies all the way to the root of the dependency tree."
    )
    parser.add_argument("--depth", help=helps, type=check_positive)
    add_version_argument(parser)
    add_verbose_argument(parser)
    helps = "Include vulnerabilities in the output of CyloneDX SBOM"
    parser.add_argument("--include-vulns", help=helps, action="store_true")
    helps = "Exclude nixpkgs metadata enrichment, including metadata-derived CPEs"
    parser.add_argument(
        "--exclude-meta", help=helps, action="store_true", default=False
    )
    helps = "Exclude heuristic CPE matching; keep exact nixpkgs metadata CPEs"
    parser.add_argument(
        "--exclude-cpe-matching", help=helps, action="store_true", default=False
    )

    group = parser.add_argument_group("output arguments")
    helps = "Path to csv output file (default: ./sbom.csv)"
    group.add_argument("--csv", nargs="?", help=helps, default="sbom.csv")
    helps = "Path to cyclonedx json output file (default: ./sbom.cdx.json)"
    group.add_argument("--cdx", nargs="?", help=helps, default="sbom.cdx.json")
    helps = "Path to spdx json output file (default: ./sbom.spdx.json)"
    group.add_argument("--spdx", nargs="?", help=helps, default="sbom.spdx.json")
    helps = "Run nix command with --impure"
    parser.add_argument("--impure", help=helps, action="store_true")

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
    started = time.perf_counter()
    resolve_started = time.perf_counter()
    target = resolve_nix_target(
        args.NIXREF, buildtime=args.buildtime, impure=args.impure
    )
    LOG.verbose(
        "Resolved CLI target in %.3fs: path='%s', flakeref='%s'",
        time.perf_counter() - resolve_started,
        target.path,
        target.flakeref,
    )
    LOG.info("Generating SBOM for target '%s'", target.path)
    build_started = time.perf_counter()
    sbom = SbomBuilder(
        nix_path=target.path,
        buildtime=args.buildtime,
        depth=args.depth,
        flakeref=target.flakeref,
        original_ref=target.original_ref,
        impure=args.impure,
        include_meta=not args.exclude_meta,
        include_vulns=args.include_vulns,
        include_cpe=not args.exclude_cpe_matching,
    )
    LOG.verbose(
        "Constructed SBOM model in %.3fs",
        time.perf_counter() - build_started,
    )
    if args.cdx:
        export_started = time.perf_counter()
        cdx = sbom.to_cdx_data()
        if args.include_vulns:
            sbom.enrich_cdx_with_vulnerabilities(cdx)
        sbom.write_json(args.cdx, cdx, printinfo=True)
        LOG.verbose(
            "Wrote CycloneDX output in %.3fs",
            time.perf_counter() - export_started,
        )
    if args.spdx:
        export_started = time.perf_counter()
        sbom.to_spdx(args.spdx)
        LOG.verbose(
            "Wrote SPDX output in %.3fs",
            time.perf_counter() - export_started,
        )
    if args.csv:
        export_started = time.perf_counter()
        sbom.to_csv(args.csv)
        LOG.verbose(
            "Wrote CSV output in %.3fs",
            time.perf_counter() - export_started,
        )
    LOG.verbose("Completed sbomnix run in %.3fs", time.perf_counter() - started)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
