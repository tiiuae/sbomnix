# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=abstract-method

"""sbomnix utils"""

import argparse
import csv
import importlib.metadata
import logging
import os
import pathlib
import re
import shlex
import subprocess
import urllib.error
from shutil import which

import packaging.version
import pandas as pd
from colorlog import ColoredFormatter, default_log_colors
from requests import Session
from requests_cache import CacheMixin
from requests_ratelimiter import LimiterMixin
from tabulate import tabulate

from common import nix_utils as _nix_utils

###############################################################################

LOG_SPAM = logging.DEBUG - 1
LOG = logging.getLogger(os.path.abspath(__file__))

# Backward-compatible re-exports for older call sites.
get_nix_store_dir = _nix_utils.get_nix_store_dir
normalize_nix_store_path = _nix_utils.normalize_nix_store_path
parse_nix_derivation_show = _nix_utils.parse_nix_derivation_show


class SbomnixError(RuntimeError):
    """Base class for expected user-facing errors."""


class FlakeRefResolutionError(SbomnixError):
    """Raised when an input looks like a flakeref but cannot be resolved."""

    def __init__(self, flakeref, stderr="", action="evaluating"):
        self.flakeref = flakeref
        self.stderr = "" if stderr is None else str(stderr)
        message = f"Failed {action} flakeref '{flakeref}'"
        stderr_summary = self.stderr.strip()
        if stderr_summary:
            message += f": {stderr_summary}"
        super().__init__(message)


class FlakeRefRealisationError(FlakeRefResolutionError):
    """Raised when a flakeref resolves but cannot be force-realised."""

    def __init__(self, flakeref, stderr=""):
        super().__init__(flakeref, stderr=stderr, action="force-realising")


class CsvLoadError(SbomnixError):
    """Raised when a CSV input cannot be read."""

    def __init__(self, name, error):
        self.name = name
        self.error = error
        super().__init__(f"Error reading csv file '{name}':\n{error}")


class CommandNotFoundError(SbomnixError):
    """Raised when a required executable is not available in PATH."""

    def __init__(self, name):
        self.name = name
        super().__init__(f"command '{name}' is not in PATH")


class InvalidNixArtifactError(SbomnixError):
    """Raised when a CLI target is not a valid nix artifact."""

    def __init__(self, path):
        self.path = path
        super().__init__(f"Specified target is not a nix artifact: '{path}'")


class MissingNixDeriverError(SbomnixError):
    """Raised when a nix artifact cannot be mapped back to a derivation."""

    def __init__(self, path):
        self.path = path
        super().__init__(f"No deriver found for: '{path}'")


class MissingNixOutPathError(SbomnixError):
    """Raised when a derivation does not expose an out path."""

    def __init__(self, path):
        self.path = path
        super().__init__(f"No outpath found for: '{path}'")


class InvalidCpeDictionaryError(SbomnixError):
    """Raised when the downloaded CPE dictionary has invalid columns."""

    def __init__(self, required_cols):
        self.required_cols = tuple(sorted(required_cols))
        super().__init__(
            f"Missing required columns {list(self.required_cols)} from cpedict"
        )


class WhitelistApplicationError(SbomnixError):
    """Raised when vulnerability whitelist application cannot proceed."""

    def __init__(self, message):
        super().__init__(message)


class InvalidSbomError(SbomnixError):
    """Raised when a supplied SBOM path is invalid."""

    def __init__(self, path):
        self.path = path
        super().__init__(f"Specified sbom target is not a json file: '{path}'")


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
    except (
        pd.errors.EmptyDataError,
        pd.errors.ParserError,
        urllib.error.HTTPError,
        urllib.error.URLError,
    ) as error:
        if exit_on_error:
            raise CsvLoadError(name, error) from error
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


def exec_cmd(cmd, raise_on_error=True, return_error=False, log_error=True, stdout=None):
    """Run shell command cmd"""
    if isinstance(cmd, (str, bytes, os.PathLike)):
        raise TypeError("cmd must be an argv sequence, not a string-like value")
    cmd = [os.fspath(part) for part in cmd]
    command_str = shlex.join(cmd)
    LOG.debug("Running: %s", command_str)
    try:
        if stdout:
            ret = subprocess.run(cmd, encoding="utf-8", check=True, stdout=stdout)
        else:
            ret = subprocess.run(cmd, capture_output=True, encoding="utf-8", check=True)
        return ret
    except subprocess.CalledProcessError as error:
        if log_error:
            LOG.error(
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


def exit_unless_command_exists(name):
    """Raise if `name` is not an executable in PATH."""
    name_is_in_path = which(name) is not None
    if not name_is_in_path:
        raise CommandNotFoundError(name)


def exit_unless_nix_artifact(path, force_realise=False):
    """
    Raise if `path` is not a nix artifact. If `force_realise` is True, run the
    nix-store-query command with `--force-realise` realising the `path`
    argument before running query.
    """
    LOG.debug("force_realize: %s", force_realise)
    if force_realise:
        LOG.info("Try force-realising store-path '%s'", path)
        cmd = ["nix-store", "-qf", path]
    else:
        cmd = ["nix-store", "-q", path]
    try:
        exec_cmd(cmd)
        return
    except subprocess.CalledProcessError:
        raise InvalidNixArtifactError(path) from None


def try_resolve_flakeref(flakeref, force_realise=False, impure=False):
    """
    Resolve flakeref to out-path, force-realising the output if `force_realise`
    is True. Returns resolved path if flakeref can be resolved to out-path.
    Returns None if the input does not appear to be a flakeref.
    Raises FlakeRefRealisationError if the flakeref resolves but realisation
    fails.
    """
    LOG.info("Evaluating '%s'", flakeref)
    cmd = nix_cmd("eval", "--raw", flakeref, impure=impure)
    ret = exec_cmd(cmd, raise_on_error=False, return_error=True, log_error=False)
    if ret is None or ret.returncode != 0:
        if _looks_like_flakeref(flakeref):
            raise FlakeRefResolutionError(flakeref, ret.stderr if ret else "")
        LOG.debug("not a flakeref: '%s'", flakeref)
        return None
    nixpath = ret.stdout.strip()
    LOG.debug("flakeref='%s' maps to path='%s'", flakeref, nixpath)
    if not force_realise:
        return nixpath
    LOG.info("Try force-realising flakeref '%s'", flakeref)
    cmd = nix_cmd("build", "--no-link", flakeref, impure=impure)
    ret = exec_cmd(cmd, raise_on_error=False, return_error=True, log_error=False)
    if ret is None or ret.returncode != 0:
        raise FlakeRefRealisationError(flakeref, ret.stderr if ret else "")
    return nixpath


def nix_cmd(*args, impure=False):
    """Build argv for nix commands that require flakes + nix-command support."""
    cmd = [
        "nix",
        *args,
        "--extra-experimental-features",
        "flakes",
        "--extra-experimental-features",
        "nix-command",
    ]
    if impure:
        cmd.append("--impure")
    return cmd


def _looks_like_flakeref(flakeref):
    """Return true if the input is likely intended as a flake reference."""
    looks_like = False
    if flakeref:
        path = pathlib.Path(flakeref)
        if path.exists():
            looks_like = path.is_dir() and (path / "flake.nix").exists()
        else:
            # Keep the heuristic to explicit flake syntax so missing local paths
            # such as ./result or foo/bar still fall back to store-path handling.
            looks_like = (
                flakeref.startswith("nixpkgs=")
                or "#" in flakeref
                or "?" in flakeref
                or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", flakeref) is not None
            )
    return looks_like


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
        LOG.debug("Unexpected v1 version '%s'", v1)
        return 0.0
    v1_major = match.group("ver_beg")
    v1_minor = match.group("ver_end").replace(".", "")
    v1_float = float(v1_major + "." + v1_minor)
    match = re.match(re_vsplit, v2_clean)
    if not match:
        LOG.debug("Unexpected v2 version '%s'", v2)
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
        LOG.debug("Unable to parse version '%s'", ver_str)
        return None
    ver_beg = match.group("ver_beg").rstrip(".")
    ver_end = match.group("ver_end")
    ver_end = re.sub(r"[^0-9.]+", "", ver_end).lstrip(".")
    if ver_end:
        ver_end = f"+{ver_end}"
    else:
        ver_end = ""
    ver_end = ver_end.rstrip(".")
    ver = f"{ver_beg}{ver_end}"
    ver = re.sub(r"\.+", ".", ver)
    LOG.log(LOG_SPAM, "%s --> %s", ver_str, ver)
    if not ver:
        LOG.debug("Invalid version '%s'", ver_str)
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


class CachedLimiterSession(CacheMixin, LimiterMixin, Session):
    """
    Session class with caching and rate-limiting
    https://requests-cache.readthedocs.io/en/stable/user_guide/compatibility.html
    """


################################################################################

set_log_verbosity(1)

################################################################################
