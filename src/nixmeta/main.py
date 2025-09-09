#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
# SPDX-License-Identifier: Apache-2.0

"""Python script for summarizing nixpkgs meta-attributes"""

import argparse
import pathlib

from common.utils import exit_unless_command_exists, set_log_verbosity
from nixmeta.scanner import NixMetaScanner

################################################################################


def _getargs():
    """Parse command line arguments"""
    desc = (
        "Summarize nix meta-attributes from the given flakeref to a csv file, "
        "optionally specifying the output attribute."
    )
    epil = "Example: nixmeta --flakeref=github:NixOS/nixpkgs/master#hello"
    parser = argparse.ArgumentParser(description=desc, epilog=epil)
    helps = (
        "Target flake reference optionally including the output attribute. "
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


def main():
    """main entry point"""
    args = _getargs()
    set_log_verbosity(args.verbose)
    # Fail early if the following commands are not in PATH
    exit_unless_command_exists("nix")
    exit_unless_command_exists("nix-env")
    # Scan metadata from the flakeref pinned nixpkgs
    scanner = NixMetaScanner()
    scanner.scan(args.flakeref)
    # Output to csv file
    scanner.to_csv(args.out, args.append)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
