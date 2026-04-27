# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""sbomnix utils"""

import argparse
import importlib.metadata
import pathlib
import re
import subprocess

import packaging.version
import pandas as pd

from common import df as _df
from common import errors as _errors
from common import http as _http
from common import log as _log
from common import nix_utils as _nix_utils
from common import proc as _proc

###############################################################################

# Backward-compatible re-exports for older call sites.
CsvLoadError = _errors.CsvLoadError
CommandNotFoundError = _errors.CommandNotFoundError
FlakeRefRealisationError = _errors.FlakeRefRealisationError
FlakeRefResolutionError = _errors.FlakeRefResolutionError
InvalidCpeDictionaryError = _errors.InvalidCpeDictionaryError
InvalidNixArtifactError = _errors.InvalidNixArtifactError
InvalidSbomError = _errors.InvalidSbomError
MissingNixDeriverError = _errors.MissingNixDeriverError
MissingNixOutPathError = _errors.MissingNixOutPathError
SbomnixError = _errors.SbomnixError
WhitelistApplicationError = _errors.WhitelistApplicationError
LOG = _log.LOG
LOG_SPAM = _log.LOG_SPAM
set_log_verbosity = _log.set_log_verbosity
CachedLimiterSession = _http.CachedLimiterSession
df_from_csv_file = _df.df_from_csv_file
df_log = _df.df_log
df_regex_filter = _df.df_regex_filter
df_to_csv_file = _df.df_to_csv_file
exec_cmd = _proc.exec_cmd
nix_cmd = _proc.nix_cmd
which = _proc.which
get_nix_store_dir = _nix_utils.get_nix_store_dir
normalize_nix_store_path = _nix_utils.normalize_nix_store_path
parse_nix_derivation_show = _nix_utils.parse_nix_derivation_show


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
