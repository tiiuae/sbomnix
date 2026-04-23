# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=abstract-method

"""sbomnix utils"""

import argparse
import csv
import importlib.metadata
import json
import logging
import os
import pathlib
import re
import shlex
import subprocess
import sys
import urllib.error
from shutil import which

import packaging.version
import pandas as pd
from colorlog import ColoredFormatter, default_log_colors
from requests import Session
from requests_cache import CacheMixin
from requests_ratelimiter import LimiterMixin
from tabulate import tabulate

###############################################################################

LOG_SPAM = logging.DEBUG - 1
LOG = logging.getLogger(os.path.abspath(__file__))
RE_NIX_STORE_PATH_BASENAME = re.compile(r"^[0-9a-z]{32}-.+")
RE_NIX_STORE_PATH = re.compile(r"(?P<store_path>/(?:[^/\s:]+/)+[0-9a-z]{32}-[^/\s:]+)")


class FlakeRefResolutionError(RuntimeError):
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
    """Check if `name` is an executable in PATH"""
    name_is_in_path = which(name) is not None
    if not name_is_in_path:
        LOG.fatal("command '%s' is not in PATH", name)
        sys.exit(1)


def exit_unless_nix_artifact(path, force_realise=False):
    """
    Exit with error if `path` is not a nix artifact. If `force_realise` is True,
    run the nix-store-query command with `--force-realise` realising the `path`
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
        LOG.fatal("Specified target is not a nix artifact: '%s'", path)
        sys.exit(1)


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


def get_nix_store_dir(path=None, default="/nix/store"):
    """Infer the nix store directory from an absolute store path-like string."""
    if path:
        match = RE_NIX_STORE_PATH.search(str(path))
        if match:
            return os.path.dirname(match.group("store_path"))
    return default


def normalize_nix_store_path(path, store_dir="/nix/store"):
    """Return an absolute store path for basename-only store path strings."""
    if not isinstance(path, str) or not path:
        return path
    if os.path.isabs(path) or not RE_NIX_STORE_PATH_BASENAME.match(path):
        return path
    return os.path.join(store_dir, path)


def _iter_nix_store_dir_candidates(value):
    """Yield strings that may reveal the nix store directory."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_nix_store_dir_candidates(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_nix_store_dir_candidates(item)


def _infer_nix_store_dir(drv_info, default="/nix/store"):
    """Infer the nix store directory from derivation fields when keys are relative."""
    if not isinstance(drv_info, dict):
        return default
    for candidate in _iter_nix_store_dir_candidates(
        {
            "builder": drv_info.get("builder"),
            "outputs": drv_info.get("outputs"),
            "env": drv_info.get("env"),
        }
    ):
        store_dir = get_nix_store_dir(candidate, default=None)
        if store_dir:
            return store_dir
    return default


def _normalize_nix_derivation_info(drv_info, store_dir):
    """Normalize basename-only store paths within derivation info."""
    if not isinstance(drv_info, dict):
        return drv_info

    normalized = dict(drv_info)

    outputs = normalized.get("outputs")
    if isinstance(outputs, dict):
        normalized["outputs"] = {}
        for name, output in outputs.items():
            if isinstance(output, dict):
                output = dict(output)
                if output.get("path"):
                    output["path"] = normalize_nix_store_path(output["path"], store_dir)
            normalized["outputs"][name] = output

    env = normalized.get("env")
    if isinstance(env, dict):
        normalized["env"] = {
            key: normalize_nix_store_path(value, store_dir)
            for key, value in env.items()
        }

    inputs = normalized.get("inputs")
    if isinstance(inputs, dict):
        normalized_inputs = dict(inputs)
        srcs = normalized_inputs.get("srcs")
        if isinstance(srcs, list):
            normalized_inputs["srcs"] = [
                normalize_nix_store_path(src, store_dir) for src in srcs
            ]
        drvs = normalized_inputs.get("drvs")
        if isinstance(drvs, dict):
            normalized_inputs["drvs"] = {
                normalize_nix_store_path(path, store_dir): outputs
                for path, outputs in drvs.items()
            }
        normalized["inputs"] = normalized_inputs

    input_srcs = normalized.get("inputSrcs")
    if isinstance(input_srcs, list):
        normalized["inputSrcs"] = [
            normalize_nix_store_path(src, store_dir) for src in input_srcs
        ]

    input_drvs = normalized.get("inputDrvs")
    if isinstance(input_drvs, dict):
        normalized["inputDrvs"] = {
            normalize_nix_store_path(path, store_dir): outputs
            for path, outputs in input_drvs.items()
        }

    return normalized


def parse_nix_derivation_show(stdout, store_path_hint=None):
    """Normalize `nix derivation show` JSON across legacy and wrapped formats."""
    payload = json.loads(stdout)
    derivations = (
        payload.get("derivations", payload) if isinstance(payload, dict) else {}
    )
    if not isinstance(derivations, dict):
        return {}

    normalized = {}
    fallback_store_dir = get_nix_store_dir(store_path_hint)
    for drv_path, drv_info in derivations.items():
        store_dir = get_nix_store_dir(drv_path, default=None)
        if not store_dir:
            store_dir = _infer_nix_store_dir(drv_info, default=fallback_store_dir)
        normalized_drv_path = normalize_nix_store_path(drv_path, store_dir)
        normalized[normalized_drv_path] = _normalize_nix_derivation_info(
            drv_info, store_dir
        )
    return normalized


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
