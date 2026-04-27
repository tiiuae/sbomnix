# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Common argparse helper functions."""

import argparse

from common.pkgmeta import get_py_pkg_version


def check_positive(val):
    """Raise ArgumentTypeError if val is not a positive integer."""
    intval = int(val)
    if intval <= 0:
        raise argparse.ArgumentTypeError(f"{val} is not a positive integer")
    return intval


def add_verbose_argument(parser, default=1, max_level=3):
    """Add a standard verbose flag to an argparse parser."""
    helps = (
        f"Set the debug verbosity level between 0-{max_level} "
        f"(default: --verbose={default})"
    )
    parser.add_argument("-v", "--verbose", help=helps, type=int, default=default)


def add_version_argument(parser, package="sbomnix"):
    """Add a standard version flag to an argparse parser."""
    parser.add_argument(
        "--version", action="version", version=get_py_pkg_version(package)
    )
