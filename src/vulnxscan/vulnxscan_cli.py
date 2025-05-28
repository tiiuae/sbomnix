#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""
Scan nix artifact or CycloneDX SBOM for vulnerabilities with various
open-source vulnerability scanners.
"""

import argparse
import logging
import pathlib
import sys
from tempfile import NamedTemporaryFile

from common.utils import (
    LOG,
    exit_unless_command_exists,
    exit_unless_nix_artifact,
    set_log_verbosity,
    try_resolve_flakeref,
)
from sbomnix.sbomdb import SbomDb
from vulnxscan.utils import _is_json
from vulnxscan.vulnscan import VulnScan

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = (
        "Scan nix artifact or CycloneDX SBOM for vulnerabilities with "
        "various open-source vulnerability scanners."
    )
    epil = "Example: ./vulnxscan.py /path/to/nix/out/or/drv/or/flakeref"
    parser = argparse.ArgumentParser(description=desc, epilog=epil)
    helps = (
        "Target nix store path (e.g. derivation file or nix output path) or flakeref"
    )
    parser.add_argument("TARGET", help=helps, type=str)
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)
    helps = "Path to output file (default: ./vulns.csv)"
    parser.add_argument("--out", nargs="?", help=helps, default="vulns.csv")
    helps = (
        "Scan target buildtime instead of runtime dependencies. This option "
        "has no impact if the scan target is SBOM (ref: --sbom)."
    )
    parser.add_argument("--buildtime", help=helps, action="store_true")
    helps = (
        "Indicate that TARGET is a cdx SBOM instead of path to nix artifact. "
        "This allows running vulnxscan using input SBOMs from any tool "
        "capable of generating cdx SBOM. This option makes it possible to run "
        "vulnxscan postmortem against any (potentially earlier) release of "
        "the TARGET. "
        "Moreover, this option allows using vulnxscan against non-nix targets "
        "as long as SBOM includes valid CPE identifiers and purls. "
        "If this option is specified, vulnix scan will not run, since vulnix "
        "is nix-only and requires components' nix store paths. "
        "Also, if this option is specified, option '--buildtime' will be "
        "ignored since target packages will be read from the given SBOM."
    )
    parser.add_argument("--sbom", help=helps, action="store_true")
    helps = (
        "Path to whitelist file. Vulnerabilities that match any whitelisted "
        "entries will not be included to the console output and are annotated "
        "accordingly in the output csv. See more details in the vulnxscan "
        "README.md."
    )
    parser.add_argument("--whitelist", help=helps, type=pathlib.Path)
    helps = (
        "Add more information to vulnxscan output by querying "
        "repology.org for available package versions in nix-unstable and "
        "package upstream. This option is intended to help manual analysis. "
        "Output is written to a separate OUT file with 'triage' infix, "
        "by default: 'vulns.triage.csv'."
    )
    parser.add_argument("--triage", help=helps, action="store_true")
    triagegr = parser.add_argument_group("Other arguments")
    helps = (
        "Search nixpkgs github for PRs that might include more information "
        "concerning possible nixpkgs fixes for the found vulnerabilities. "
        "This option adds URLs to (at most five) PRs that appear valid "
        "for each vulnerability based on heuristic. "
        "The PR search takes significant "
        "time due to github API rate limits, which is why this feature is "
        "not enabled by default. This option has no impact unless '--triage' "
        "is also specified."
    )
    triagegr.add_argument("--nixprs", help=helps, action="store_true")
    return parser.parse_args()


################################################################################


def _generate_sbom(target_path, buildtime=False):
    LOG.info("Generating SBOM for target '%s'", target_path)
    sbomdb = SbomDb(target_path, buildtime, include_meta=False)
    prefix = "vulnxscan_"
    cdx_suffix = ".json"
    csv_suffix = ".csv"
    with (
        NamedTemporaryFile(delete=False, prefix=prefix, suffix=cdx_suffix) as fcdx,
        NamedTemporaryFile(delete=False, prefix=prefix, suffix=csv_suffix) as fcsv,
    ):
        sbomdb.to_cdx(fcdx.name, printinfo=False)
        sbomdb.to_csv(fcsv.name, loglevel=logging.DEBUG)
        return pathlib.Path(fcdx.name), pathlib.Path(fcsv.name)


################################################################################


# Main


def main():
    """main entry point"""
    args = getargs()
    set_log_verbosity(args.verbose)

    # Fail early if following commands are not in path
    exit_unless_command_exists("grype")
    exit_unless_command_exists("vulnix")

    scanner = VulnScan()
    if args.sbom:
        target_path = pathlib.Path(args.TARGET).resolve().as_posix()
        if not _is_json(target_path):
            LOG.fatal(
                "Specified sbom target is not a json file: '%s'", str(args.TARGET)
            )
            sys.exit(0)
        sbom_cdx_path = target_path
        sbom_csv_path = None
    else:
        runtime = args.buildtime is False
        target_path = try_resolve_flakeref(args.TARGET, force_realise=runtime)
        if not target_path:
            target_path = pathlib.Path(args.TARGET).resolve().as_posix()
            exit_unless_nix_artifact(args.TARGET, force_realise=runtime)
        sbom_cdx_path, sbom_csv_path = _generate_sbom(target_path, args.buildtime)
        LOG.debug("Using cdx SBOM '%s'", sbom_cdx_path)
        LOG.debug("Using csv SBOM '%s'", sbom_csv_path)
        scanner.scan_vulnix(target_path, args.buildtime)
    scanner.scan_grype(sbom_cdx_path)
    scanner.scan_osv(sbom_cdx_path)
    scanner.report(args, sbom_csv_path)
    if not args.sbom and LOG.level > logging.DEBUG:
        # Remove generated temp files unless verbosity is DEBUG or more verbose
        sbom_cdx_path.unlink(missing_ok=True)
        sbom_csv_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()

################################################################################
