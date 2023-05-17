# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name

""" sbomnix utils """

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

LOGGER_NAME = "sbomnix-logger"
LOG_SPAM = logging.DEBUG - 1

###############################################################################


def df_to_csv_file(df, name, loglevel=logging.INFO):
    """Write dataframe to csv file"""
    df.to_csv(
        path_or_buf=name, quoting=csv.QUOTE_ALL, sep=",", index=False, encoding="utf-8"
    )
    logging.getLogger(LOGGER_NAME).log(loglevel, "Wrote: %s", name)


def df_from_csv_file(name):
    """Read csv file into dataframe"""
    logging.getLogger(LOGGER_NAME).debug("Reading: %s", name)
    try:
        df = pd.read_csv(name, keep_default_na=False, dtype=str)
        df.reset_index(drop=True, inplace=True)
        return df
    except pd.errors.ParserError:
        logging.getLogger(LOGGER_NAME).fatal("Not a csv file: '%s'", name)
        sys.exit(1)


def df_regex_filter(df, column, regex):
    """Return rows where column 'column' values match the given regex"""
    logging.getLogger(LOGGER_NAME).debug("column:'%s', regex:'%s'", column, regex)
    return df[df[column].str.contains(regex, regex=True, na=False)]


def df_log(df, loglevel, tablefmt="presto"):
    """Log dataframe with given loglevel and tablefmt"""
    if logging.getLogger(LOGGER_NAME).level <= loglevel:
        if df.empty:
            return
        df = df.fillna("")
        table = tabulate(
            df, headers="keys", tablefmt=tablefmt, stralign="left", showindex=False
        )
        logging.getLogger(LOGGER_NAME).log(loglevel, "\n%s\n", table)


def setup_logging(verbosity=1):
    """Setup logging with specified verbosity"""
    project_logger = logging.getLogger(LOGGER_NAME)

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

    default_log_colors["INFO"] = "fg_bold_white"
    default_log_colors["DEBUG"] = "fg_bold_white"
    default_log_colors["SPAM"] = "fg_bold_white"
    formatter = ColoredFormatter(logformat, log_colors=default_log_colors)
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logging.addLevelName(LOG_SPAM, "SPAM")
    project_logger.addHandler(stream)
    project_logger.setLevel(level)


def exec_cmd(cmd, raise_on_error=True, return_error=False):
    """Run shell command cmd"""
    command_str = " ".join(cmd)
    logging.getLogger(LOGGER_NAME).debug("Running: %s", command_str)
    try:
        ret = subprocess.run(cmd, capture_output=True, encoding="utf-8", check=True)
        return ret.stdout
    except subprocess.CalledProcessError as error:
        logging.getLogger(LOGGER_NAME).debug(
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
    Return float value between [0.0,1.0] indicating the closeness
    of the given two numbers.
    Returns 1.0 if the two integers are equal.
    Returns 0.0 if either argument is not a number.
    """
    if not isinstance(n1, (float, int)) or not isinstance(n2, (float, int)):
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
    re_vclean = re.compile(r"[^0-9.]+")
    v1_clean = re_vclean.sub(r"", v1)
    v2_clean = re_vclean.sub(r"", v2)
    re_vsplit = re.compile(r"(?P<ver_beg>[0-9][0-9]*)(?P<ver_end>.*)$")
    match = re.match(re_vsplit, v1_clean)
    if not match:
        logging.getLogger(LOGGER_NAME).warning("Unexpected v1 version '%s'", v1)
        return 0.0
    v1_major = match.group("ver_beg")
    v1_minor = match.group("ver_end").replace(".", "")
    v1_float = float(v1_major + "." + v1_minor)
    match = re.match(re_vsplit, v2_clean)
    if not match:
        logging.getLogger(LOGGER_NAME).warning("Unexpected v2 version '%s'", v2)
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
    re_ver = re.compile(r"(?P<ver_beg>[0-9][0-9.]*)(?P<ver_end>.*)$")
    match = re_ver.match(ver_str)
    if not match:
        logging.getLogger(LOGGER_NAME).warning("Unable to parse version '%s'", ver_str)
        return None
    ver_beg = match.group("ver_beg").rstrip(".")
    ver_end = match.group("ver_end")
    re_vclean = re.compile("[^0-9.]+")
    ver_end = re_vclean.sub(r"", ver_end)
    if ver_end:
        ver_end = f"+{ver_end}"
    else:
        ver_end = ""
    ver_end = ver_end.rstrip(".")
    ver = f"{ver_beg}{ver_end}"
    logging.getLogger(LOGGER_NAME).log(LOG_SPAM, "%s --> %s", ver_str, ver)
    if not ver:
        logging.getLogger(LOGGER_NAME).warning("Invalid version '%s'", ver_str)
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


################################################################################
