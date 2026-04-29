# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Common argparse helper functions."""

import argparse
import sys
from weakref import WeakSet

from common.pkgmeta import get_py_pkg_version

_VERBOSE_COUNT_DEST = "_verbose_count"
_VERBOSE_WRAPPED_PARSERS = WeakSet()


class _VerboseCountAction(argparse.Action):
    """Count repeated short verbose flags without using parser defaults."""

    def __init__(self, option_strings, dest, nargs=0, **kwargs):
        if nargs != 0:
            raise ValueError("nargs must be 0")
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, _parser, namespace, _values, _option_string=None):
        count = getattr(namespace, _VERBOSE_COUNT_DEST, 0) + 1
        setattr(namespace, _VERBOSE_COUNT_DEST, count)
        setattr(namespace, self.dest, count)


def check_positive(val):
    """Raise ArgumentTypeError if val is not a positive integer."""
    intval = int(val)
    if intval <= 0:
        raise argparse.ArgumentTypeError(f"{val} is not a positive integer")
    return intval


def _is_integer(value):
    """Return True if value can be parsed as an integer."""
    try:
        int(value)
    except ValueError:
        return False
    return True


def _normalize_verbose_args(args):
    """Normalize compact short verbose values before argparse sees positionals."""
    normalized = []
    args = list(sys.argv[1:] if args is None else args)
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "-v" and idx + 1 < len(args) and _is_integer(args[idx + 1]):
            normalized.append(f"--verbose={args[idx + 1]}")
            idx += 2
            continue
        if arg.startswith("-v") and arg != "-v":
            value = arg[2:]
            if value.startswith("="):
                value = value[1:]
            if value and _is_integer(value):
                normalized.append(f"--verbose={value}")
                idx += 1
                continue
        normalized.append(arg)
        idx += 1
    return normalized


def _finalize_verbose_namespace(namespace):
    """Remove internal argparse bookkeeping from the parsed namespace."""
    if hasattr(namespace, _VERBOSE_COUNT_DEST):
        delattr(namespace, _VERBOSE_COUNT_DEST)
    return namespace


def _wrap_verbose_parser(parser):
    """Teach parse_known_args to normalize compact short verbose values."""
    if parser in _VERBOSE_WRAPPED_PARSERS:
        return

    parse_known_args = parser.parse_known_args

    def parse_known_args_with_verbose(args=None, namespace=None):
        namespace, extras = parse_known_args(
            _normalize_verbose_args(args),
            namespace,
        )
        return _finalize_verbose_namespace(namespace), extras

    parser.parse_known_args = parse_known_args_with_verbose
    _VERBOSE_WRAPPED_PARSERS.add(parser)


def add_verbose_argument(parser, default=0, max_level=3, root_parser=None):
    """Add a standard verbose flag to an argparse parser."""
    _wrap_verbose_parser(root_parser or parser)
    parser.set_defaults(verbose=default, **{_VERBOSE_COUNT_DEST: 0})
    levels = ["0=INFO", "1=VERBOSE", "2=DEBUG", "3=SPAM"]
    level_help = ", ".join(levels[: max_level + 1])
    short_help = (
        f"Increase verbosity; repeat as -vv for DEBUG (default: --verbose={default})"
    )
    long_help = (
        f"Set verbosity level explicitly ({level_help}) (default: --verbose={default})"
    )
    parser.add_argument(
        "-v",
        action=_VerboseCountAction,
        dest="verbose",
        help=short_help,
    )
    parser.add_argument(
        "--verbose",
        type=int,
        dest="verbose",
        metavar="N",
        help=long_help,
    )


def add_version_argument(parser, package="sbomnix"):
    """Add a standard version flag to an argparse parser."""
    parser.add_argument(
        "--version", action="version", version=get_py_pkg_version(package)
    )
