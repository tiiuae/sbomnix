#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
# SPDX-License-Identifier: Apache-2.0

""" Python script for summarizing nixpkgs meta-attributes """

import sys
import argparse
import pathlib
import shutil
from nixmeta.scanner import NixMetaScanner
from common.utils import LOG, set_log_verbosity


################################################################################


def _getargs():
    """Parse command line arguments"""
    desc = (
        "Summarize nixpkgs meta-attributes from the given nixpkgs version "
        "to a csv output file."
    )
    epil = "Example: nixmeta --flakeref=github:NixOS/nixpkgs?ref=master"
    parser = argparse.ArgumentParser(description=desc, epilog=epil)
    helps = (
        "Flake reference specifying the location of the flake "
        "from which the pinned nixpkgs target version is read. "
        "The default value is the "
        "current nixpkgs version in its 'nixos-unstable' branch. "
        "For more details, see: "
        "https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-flake"
        "#flake-references and "
        "https://nixos.wiki/wiki/Nix_channels "
        "(default: --flakeref=github:NixOS/nixpkgs?ref=nixos-unstable)."
    )
    parser.add_argument(
        "-f",
        "--flakeref",
        help=helps,
        type=str,
        default="github:NixOS/nixpkgs?ref=nixos-unstable",
    )
    helps = "Path to output file (default: --out=nixmeta.csv)."
    parser.add_argument(
        "-o",
        "--out",
        help=helps,
        type=pathlib.Path,
        default="nixmeta.csv",
    )
    helps = (
        "Append to output file - removing duplicate entries - instead of "
        "completely overwriting possible earlier output file."
    )
    parser.add_argument(
        "-a",
        "--append",
        help=helps,
        action="store_true",
    )
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)."
    parser.add_argument("-v", "--verbose", help=helps, type=int, default=1)
    return parser.parse_args()


###############################################################################


def _exit_unless_command_exists(name):
    """Check if `name` is an executable in PATH"""
    name_is_in_path = shutil.which(name) is not None
    if not name_is_in_path:
        LOG.fatal("command '%s' is not in PATH", name)
        sys.exit(1)


###############################################################################


def main():
    """main entry point"""
    args = _getargs()
    set_log_verbosity(args.verbose)
    # Fail early if the following commands are not in PATH
    _exit_unless_command_exists("nix")
    _exit_unless_command_exists("nix-env")
    # Scan metadata from the flakeref pinned nixpkgs
    scanner = NixMetaScanner()
    scanner.scan(args.flakeref)
    # Output to csv file
    scanner.to_csv(args.out, args.append)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
