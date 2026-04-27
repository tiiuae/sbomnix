# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""sbomnix utils"""

import argparse
import importlib.metadata
import pathlib
import re
import subprocess

import pandas as _pandas

from common import df as _df
from common import errors as _errors
from common import http as _http
from common import log as _log
from common import nix_utils as _nix_utils
from common import package_names as _package_names
from common import proc as _proc
from common import versioning as _versioning

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
pd = _pandas
get_nix_store_dir = _nix_utils.get_nix_store_dir
normalize_nix_store_path = _nix_utils.normalize_nix_store_path
parse_nix_derivation_show = _nix_utils.parse_nix_derivation_show
number_distance = _versioning.number_distance
version_distance = _versioning.version_distance
parse_version = _versioning.parse_version
nix_to_repology_pkg_name = _package_names.nix_to_repology_pkg_name


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


def check_positive(val):
    """Raise ArgumentTypeError if val is not a positive integer"""
    intval = int(val)
    if intval <= 0:
        raise argparse.ArgumentTypeError(f"{val} is not a positive integer")
    return intval
