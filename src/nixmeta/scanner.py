#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
# SPDX-License-Identifier: Apache-2.0

"""Summarize nixpkgs meta-attributes"""

import json
import pathlib
import re
from getpass import getuser
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory, gettempdir

import pandas as pd
from filelock import FileLock

from common.utils import LOG, LOG_SPAM, df_from_csv_file, df_to_csv_file, exec_cmd
from sbomnix.dfcache import LockedDfCache

###############################################################################

_NIXMETA_NIXPKGS_TTL = 60 * 60 * 24 * 30
_FLOCK = pathlib.Path(gettempdir()) / f"{getuser()}_sbomnix_meta.lock"

###############################################################################


class NixMetaScanner:
    """Scan nixpkgs meta-info"""

    def __init__(self):
        self.df_meta = None
        self.lock = FileLock(_FLOCK)
        self.cache = LockedDfCache()
        self.attr = "default"
        self.flakeref = None
        self.resolved = None

    def scan(self, nixref):
        """
        Scan nix meta-attributes from the given nixref
        """
        self.flakeref = "" if not nixref else str(nixref)
        match = re.match(r"([^#]+)#(.*)", self.flakeref)
        if match:
            self.flakeref = match.group(1)
            self.attr = match.group(2)
        meta_json = _get_flake_metadata(self.flakeref)
        if meta_json and "url" in meta_json:
            self.flakeref = meta_json["url"]
            self.resolved = f"{self.flakeref}#{self.attr}"
            LOG.debug("Resolved flakeref '%s' ==> '%s'", self.flakeref, self.resolved)
        # Try reading nix meta with meta.nix: this works if nixref is
        # a flake reference with output attribute
        if self.resolved and self._read_flake_meta(self.resolved):
            LOG.debug("Nix meta from meta.nix")
            return
        # Otherwise, fallback to reading nix meta using the nixpkgs
        # version pinned in nixref
        nixpkgs_path = self._nixref_to_nixpkgs_path(meta_json)
        if not nixpkgs_path:
            return
        if not nixpkgs_path.exists():
            LOG.warning("Nixpkgs not in nix store: %s", nixpkgs_path.as_posix())
            return
        LOG.debug("nixpkgs: %s", nixpkgs_path)
        self._read_nixpkgs_meta(nixpkgs_path.as_posix())

    def to_csv(self, csv_path, append=False):
        """Export meta-info to a csv file"""
        csv_path = pathlib.Path(csv_path)
        if append and csv_path.exists():
            df = df_from_csv_file(csv_path)
            self.df_meta = pd.concat([self.df_meta, df], ignore_index=True)
            self._drop_duplicates()
        if self.df_meta is None or self.df_meta.empty:
            LOG.info("Nothing to output")
            return
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        df_to_csv_file(self.df_meta, csv_path.absolute().as_posix())

    def to_df(self):
        """Return meta-info as dataframe"""
        return self.df_meta

    def _read_flake_meta(self, nixref):
        with TemporaryDirectory(delete=True, prefix="nixmeta_") as tmpdir:
            meta_nix_path = Path(__file__).parent.resolve() / "meta.nix"
            outname = Path(tmpdir) / "meta.nix.out"
            cmd = [
                "nix",
                "build",
                "-f",
                meta_nix_path.as_posix(),
                "--out-link",
                outname.as_posix(),
                "--argstr",
                "flakeStr",
                nixref,
            ]
            if not exec_cmd(cmd, raise_on_error=False):
                LOG.debug("Failed reading meta with meta.nix")
                return False
            LOG.debug("Read nix meta with meta.nix")
            self.df_meta = _parse_json_metadata(outname.as_posix())
            self._drop_duplicates()
            return True

    def _read_nixpkgs_meta(self, nixpkgs_path):
        with self.lock:
            self.df_meta = self.cache.get(nixpkgs_path)
            if self.df_meta is not None and not self.df_meta.empty:
                LOG.debug("found from cache: %s", nixpkgs_path)
                return
            LOG.debug("cache miss, scanning: %s", nixpkgs_path)
            prefix = "nixmeta_"
            suffix = ".json"
            with NamedTemporaryFile(delete=True, prefix=prefix, suffix=suffix) as f:
                cmd = [
                    "nix-env",
                    "-qa",
                    "--meta",
                    "--json",
                    "-f",
                    nixpkgs_path,
                    "--arg",
                    "config",
                    "{allowAliases=false;}",
                ]
                exec_cmd(cmd, stdout=f)
                LOG.debug("Generated meta.json: %s", f.name)
                self.df_meta = _parse_json_metadata(f.name)
                self._drop_duplicates()
            # Cache requires some TTL, so we set it to some value here.
            # Although, we could as well store it indefinitely as it should
            # not change given the same key (nixpkgs store path).
            self.cache.set(
                key=nixpkgs_path, value=self.df_meta, ttl=_NIXMETA_NIXPKGS_TTL
            )

    def _drop_duplicates(self):
        self.df_meta = self.df_meta.astype(str)
        self.df_meta.fillna("", inplace=True)
        uids = [
            "name",
            "version",
            "meta_license_short",
            "meta_license_spdxid",
            "meta_homepage",
        ]
        self.df_meta.sort_values(by=uids, inplace=True)
        self.df_meta.drop_duplicates(subset=uids, keep="last", inplace=True)

    def _nixref_to_nixpkgs_path(self, meta_json):
        """Return the store path of the nixpkgs in meta_json"""
        if not _is_nixpkgs_metadata(meta_json):
            # If flakeref is not nixpkgs flake, try finding the nixpkgs
            # revision pinned by the given flakeref
            LOG.debug("non-nixpkgs flakeref: %s", self.flakeref)
            nixpkgs_flakeref = _get_nixpkgs_flakeref(meta_json)
            if not nixpkgs_flakeref:
                LOG.warning("Failed parsing locked nixpkgs: %s", self.flakeref)
                return None
            LOG.log(LOG_SPAM, "using nixpkgs_flakeref: %s", nixpkgs_flakeref)
            meta_json = _get_flake_metadata(nixpkgs_flakeref)
            if not _is_nixpkgs_metadata(meta_json):
                LOG.warning("Failed reading nixpkgs metadata: %s", self.flakeref)
                return None
        return pathlib.Path(meta_json["path"]).absolute()


###############################################################################


def _get_flake_metadata(flakeref):
    """
    Return json object detailing the output of nix flake metadata
    for given flakeref
    """
    # Strip possible nixpkgs= prefix to support cases where flakeref is
    # given the NIX_PATH environment variable
    m_nixpkgs = re.match(r"nixpkgs=([^:\s]+)", flakeref)
    if m_nixpkgs:
        flakeref = m_nixpkgs.group(1)
    # Read nix flake metadata as json
    exp = "--extra-experimental-features flakes "
    exp += "--extra-experimental-features nix-command"
    cmd = f"nix flake metadata {flakeref} --json {exp}"
    ret = exec_cmd(cmd.split(), raise_on_error=False, return_error=True)
    if ret is None or ret.returncode != 0:
        LOG.debug("Failed reading flake metadata: %s", flakeref)
        return None
    meta_json = json.loads(ret.stdout)
    LOG.log(LOG_SPAM, meta_json)
    return meta_json


def _is_nixpkgs_metadata(meta_json):
    """Return true if meta_json describes nixpkgs flakeref"""
    try:
        # Needed to support cases where flakeref is a nix store path
        # to nixpkgs-source directory
        if (
            "path" in meta_json
            and "description" in meta_json
            and meta_json["description"]
            == "A collection of packages for the Nix package manager"
        ):
            return True
        if (
            "path" in meta_json
            and meta_json["locked"]["owner"] == "NixOS"
            and meta_json["locked"]["repo"] == "nixpkgs"
        ):
            return True
    except (KeyError, TypeError):
        return False
    return False


def _get_flake_nixpkgs_val(meta_json, key):
    """Given nixpkgs flake metadata, return the locked key"""
    try:
        return meta_json["locks"]["nodes"]["nixpkgs"]["locked"][key]
    except (KeyError, TypeError):
        return None


def _get_flake_nixpkgs_obj(meta_json):
    """Given nixpkgs flake metadata, return the locked nixpkgs object"""
    try:
        return meta_json["locks"]["nodes"]["nixpkgs"]["locked"]
    except (KeyError, TypeError):
        return None


def _get_nixpkgs_flakeref_github(meta_json):
    owner = _get_flake_nixpkgs_val(meta_json, "owner")
    repo = _get_flake_nixpkgs_val(meta_json, "repo")
    rev = _get_flake_nixpkgs_val(meta_json, "rev")
    if None in [owner, repo, rev]:
        LOG.debug(
            "owner, repo, or rev not found: %s", _get_flake_nixpkgs_obj(meta_json)
        )
        return None
    return f"github:{owner}/{repo}?rev={rev}"


def _get_nixpkgs_flakeref_git(meta_json):
    url = _get_flake_nixpkgs_val(meta_json, "url")
    rev = _get_flake_nixpkgs_val(meta_json, "rev")
    ref = _get_flake_nixpkgs_val(meta_json, "ref")
    if None in [url, rev, ref]:
        LOG.debug("url, rev, or ref not found: %s", _get_flake_nixpkgs_obj(meta_json))
        return None
    return f"git+{url}?ref={ref}&rev={rev}"


def _get_nixpkgs_flakeref_path(meta_json):
    path = _get_flake_nixpkgs_val(meta_json, "path")
    if None in [path]:
        LOG.debug("path not found: %s", _get_flake_nixpkgs_obj(meta_json))
        return None
    return f"path:{path}"


def _get_nixpkgs_flakeref_tarball(meta_json):
    url = _get_flake_nixpkgs_val(meta_json, "url")
    if None in [url]:
        LOG.debug("url not found: %s", _get_flake_nixpkgs_obj(meta_json))
        return None
    return f"{url}"


def _get_nixpkgs_flakeref(meta_json):
    """Given nixpkgs flake metadata, return the locked ref"""
    _type = _get_flake_nixpkgs_val(meta_json, "type")
    nixpkgs_flakeref = None
    if _type == "github":
        nixpkgs_flakeref = _get_nixpkgs_flakeref_github(meta_json)
    elif _type == "git":
        nixpkgs_flakeref = _get_nixpkgs_flakeref_git(meta_json)
    elif _type == "path":
        nixpkgs_flakeref = _get_nixpkgs_flakeref_path(meta_json)
    elif _type == "tarball":
        nixpkgs_flakeref = _get_nixpkgs_flakeref_tarball(meta_json)
    else:
        LOG.debug("Unsupported nixpkgs locked type: %s", _type)
    return nixpkgs_flakeref


def _parse_meta_entry(meta, key):
    """Parse the given key from the metadata entry"""
    items = []
    if isinstance(meta, dict):
        items.extend([_parse_meta_entry(meta.get(key, ""), key)])
    elif isinstance(meta, list):
        items.extend([_parse_meta_entry(x, key) for x in meta])
    else:
        return str(meta)
    return ";".join(list(filter(None, items)))


def _parse_json_metadata(json_filename):
    """Parse package metadata from the specified json file"""
    with open(json_filename, "r", encoding="utf-8") as inf:
        LOG.debug('Loading meta-info from "%s"', json_filename)
        json_dict = json.loads(inf.read())
        dict_selected = {}
        setcol = dict_selected.setdefault
        for _, pkg in json_dict.items():
            # generic package info
            setcol("name", []).append(pkg.get("name", ""))
            setcol("pname", []).append(pkg.get("pname", ""))
            setcol("version", []).append(pkg.get("version", ""))
            # meta
            meta = pkg.get("meta", {})
            homepage = _parse_meta_entry(meta, key="homepage")
            setcol("meta_homepage", []).append(homepage)
            setcol("meta_unfree", []).append(meta.get("unfree", ""))
            setcol("meta_description", []).append(meta.get("description", ""))
            # meta.license
            meta_license = meta.get("license", {})
            license_short = _parse_meta_entry(meta_license, key="shortName")
            setcol("meta_license_short", []).append(license_short)
            license_spdx = _parse_meta_entry(meta_license, key="spdxId")
            setcol("meta_license_spdxid", []).append(license_spdx)
            # meta.maintainers
            meta_maintainers = meta.get("maintainers", {})
            emails = _parse_meta_entry(meta_maintainers, key="email")
            setcol("meta_maintainers_email", []).append(emails)
        return pd.DataFrame(dict_selected).astype(str)


###############################################################################
