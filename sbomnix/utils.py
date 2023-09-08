# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name

""" sbomnix utils """

import os
import argparse
import re
import sys
import csv
import logging
import subprocess
import importlib.metadata
import packaging.version
from tabulate import tabulate
from colorlog import ColoredFormatter, default_log_colors
import pandas as pd

###############################################################################

LOG_SPAM = logging.DEBUG - 1
LOG = logging.getLogger(os.path.abspath(__file__))

###############################################################################


def set_log_verbosity(verbosity=1):
    """Set logging verbosity"""
    log_levels = [logging.NOTSET, logging.INFO, logging.DEBUG, LOG_SPAM]
    verbosity = min(len(log_levels) - 1, max(verbosity, 0))
    _init_logging(verbosity)


def _init_logging(verbosity=1):
    """Initialize logging"""
    if verbosity == 0:
        level = logging.NOTSET
    elif verbosity == 1:
        level = logging.INFO
    elif verbosity == 2:
        level = logging.DEBUG
    else:
        level = LOG_SPAM
    if level <= logging.DEBUG:
        logformat = (
            "%(log_color)s%(levelname)-8s%(reset)s "
            "%(filename)s:%(funcName)s():%(lineno)d "
            "%(message)s"
        )
    else:
        logformat = "%(log_color)s%(levelname)-8s%(reset)s %(message)s"
    logging.addLevelName(LOG_SPAM, "SPAM")
    default_log_colors["INFO"] = "fg_bold_white"
    default_log_colors["DEBUG"] = "fg_bold_white"
    default_log_colors["SPAM"] = "fg_bold_white"
    formatter = ColoredFormatter(logformat, log_colors=default_log_colors)
    if LOG.hasHandlers() and len(LOG.handlers) > 0:
        stream = LOG.handlers[0]
    else:
        stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    if not LOG.hasHandlers():
        LOG.addHandler(stream)
    LOG.setLevel(level)


def df_to_csv_file(df, name, loglevel=logging.INFO):
    """Write dataframe to csv file"""
    df.to_csv(
        path_or_buf=name, quoting=csv.QUOTE_ALL, sep=",", index=False, encoding="utf-8"
    )
    LOG.log(loglevel, "Wrote: %s", name)


def df_from_csv_file(name, exit_on_error=True):
    """Read csv file into dataframe"""
    LOG.debug("Reading: %s", name)
    try:
        df = pd.read_csv(name, keep_default_na=False, dtype=str)
        df.reset_index(drop=True, inplace=True)
        return df
    except (pd.errors.EmptyDataError, pd.errors.ParserError) as error:
        if exit_on_error:
            LOG.fatal("Error reading csv file '%s':\n%s", name, error)
            sys.exit(1)
        LOG.debug("Error reading csv file '%s':\n%s", name, error)
        return None


def df_regex_filter(df, column, regex):
    """Return rows where column 'column' values match the given regex"""
    LOG.debug("column:'%s', regex:'%s'", column, regex)
    return df[df[column].str.contains(regex, regex=True, na=False)]


def df_log(df, loglevel, tablefmt="presto"):
    """Log dataframe with given loglevel and tablefmt"""
    if LOG.level <= loglevel:
        if df.empty:
            return
        df = df.fillna("")
        table = tabulate(
            df, headers="keys", tablefmt=tablefmt, stralign="left", showindex=False
        )
        LOG.log(loglevel, "\n%s\n", table)


def exec_cmd(cmd, raise_on_error=True, return_error=False, loglevel=logging.DEBUG):
    """Run shell command cmd"""
    command_str = " ".join(cmd)
    LOG.log(loglevel, "Running: %s", command_str)
    try:
        return subprocess.run(cmd, capture_output=True, encoding="utf-8", check=True)
    except subprocess.CalledProcessError as error:
        LOG.debug(
            "Error running shell command:\n cmd:   '%s'\n stdout: %s\n stderr: %s",
            command_str,
            error.stdout,
            error.stderr,
        )
        if raise_on_error:
            raise error
        if return_error:
            return error
        return None


def exit_unless_nix_artifact(path, force_realise=False):
    """
    Exit with error if `path` is not a nix artifact. If `force_realize` is True,
    run the nix-store-query command with `--force-realize` realising the `path`
    argument before running query.
    """
    LOG.debug("force_realize: %s", force_realise)
    if force_realise:
        cmd = ["nix-store", "-qf", path]
    else:
        cmd = ["nix-store", "-q", path]
    try:
        exec_cmd(cmd)
        return
    except subprocess.CalledProcessError:
        LOG.fatal("Specified target is not a nix artifact: '%s'", path)
        sys.exit(1)


def regex_match(regex, string):
    """Return True if regex matches string"""
    if not regex or not string:
        return False
    return re.match(regex, string) is not None


def get_py_pkg_version(package="sbomnix"):
    """Return package version string"""
    versionstr = ""
    try:
        versionstr = importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        versionstr = "0.0.0"
    return versionstr


def number_distance(n1, n2):
    """
    Return float value between [0.0,1.0] indicating the distance
    between two non-negative numbers.
    Returns 1.0 if the two numbers are equal.
    Returns 0.0 if either argument is not a non-negative number.
    """
    if (
        not isinstance(n1, (float, int))
        or not isinstance(n2, (float, int))
        or n1 < 0
        or n2 < 0
    ):
        return 0.0
    min_n = min(n1, n2)
    max_n = max(n1, n2)
    if max_n == 0:
        return 1.0
    if min_n == 0:
        min_n += 1
        max_n += 1
    return min_n / max_n


def version_distance(v1, v2):
    """
    Return float value between [0.0,1.0] indicating the closeness
    of the given two version number strings.
    """
    v1 = str(v1)
    v2 = str(v2)
    v1_clean = re.sub(r"[^0-9.]+", "", v1)
    v2_clean = re.sub(r"[^0-9.]+", "", v2)
    re_vsplit = re.compile(r".*?(?P<ver_beg>[0-9][0-9]*)(?P<ver_end>.*)$")
    match = re.match(re_vsplit, v1_clean)
    if not match:
        LOG.warning("Unexpected v1 version '%s'", v1)
        return 0.0
    v1_major = match.group("ver_beg")
    v1_minor = match.group("ver_end").replace(".", "")
    v1_float = float(v1_major + "." + v1_minor)
    match = re.match(re_vsplit, v2_clean)
    if not match:
        LOG.warning("Unexpected v2 version '%s'", v2)
        return 0.0
    v2_major = match.group("ver_beg")
    v2_minor = match.group("ver_end").replace(".", "")
    v2_float = float(v2_major + "." + v2_minor)
    return number_distance(v1_float, v2_float)


def parse_version(ver_str):
    """
    Return comparable version object from the given version string.
    Returns None if the version string can not be converted to version object.
    """
    ver_str = str(ver_str)
    if not ver_str:
        return None
    re_ver = re.compile(r".*?(?P<ver_beg>[0-9][0-9.]*)(?P<ver_end>.*)$")
    match = re_ver.match(ver_str)
    if not match:
        LOG.warning("Unable to parse version '%s'", ver_str)
        return None
    ver_beg = match.group("ver_beg").rstrip(".")
    ver_end = match.group("ver_end")
    ver_end = re.sub(r"[^0-9.]+", "", ver_end)
    if ver_end:
        ver_end = f"+{ver_end}"
    else:
        ver_end = ""
    ver_end = ver_end.rstrip(".")
    ver = f"{ver_beg}{ver_end}"
    ver = re.sub(r"\.+", ".", ver)
    LOG.log(LOG_SPAM, "%s --> %s", ver_str, ver)
    if not ver:
        LOG.warning("Invalid version '%s'", ver_str)
        return None
    return packaging.version.parse(ver)


def nix_to_repology_pkg_name(nix_pkg_name):
    """Convert nix package name to repology package name"""
    if not nix_pkg_name or pd.isnull(nix_pkg_name):
        return nix_pkg_name
    # Convert nix_pkg_name so it matches repology package name
    nix_pkg_name = nix_pkg_name.lower()
    re_nix_to_repo = re.compile(
        r"^(?:"
        r"(python)|(perl)|(emacs)|(vim)plugin|(ocaml)|"
        r"(gnome)-shell-extension|(lisp)|(ruby)|(lua)|"
        r"(php)[0-9]*Packages|(go)|(coq)|(rust)"
        r")"
        r"[0-9.]*-(.+)"
    )
    match = re.match(re_nix_to_repo, nix_pkg_name)
    if match:
        # Filter out all non-matched groups
        matches = list(filter(None, match.groups()))
        assert len(matches) == 2, f"Unexpected package name '{nix_pkg_name}'"
        nix_pkg_name = f"{matches[0]}:{matches[1]}"
    if nix_pkg_name == "python3":
        nix_pkg_name = "python"
    if nix_pkg_name == "libtiff":
        nix_pkg_name = "tiff"
    return nix_pkg_name


def check_positive(val):
    """Raise ArgumentTypeError if val is not a positive integer"""
    intval = int(val)
    if intval <= 0:
        raise argparse.ArgumentTypeError(f"{val} is not a positive integer")
    return intval


################################################################################

set_log_verbosity(1)

################################################################################
