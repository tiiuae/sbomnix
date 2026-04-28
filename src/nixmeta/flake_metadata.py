# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for resolving nixpkgs metadata from flakerefs."""

import json
import pathlib
import re

from common.log import LOG, LOG_SPAM
from common.proc import exec_cmd, nix_cmd


def get_flake_metadata(flakeref, *, exec_cmd_fn=exec_cmd, nix_cmd_fn=nix_cmd, log=LOG):
    """Return ``nix flake metadata`` JSON for the given flakeref."""
    if flakeref.startswith("nixpkgs="):
        flakeref = flakeref.removeprefix("nixpkgs=")
    log.info("Reading flake metadata for '%s'", flakeref)
    cmd = nix_cmd_fn("flake", "metadata", flakeref, "--json")
    ret = exec_cmd_fn(cmd, raise_on_error=False, return_error=True, log_error=False)
    if ret is None or ret.returncode != 0:
        log.warning("Failed reading flake metadata: %s", flakeref)
        return None
    meta_json = json.loads(ret.stdout)
    log.log(LOG_SPAM, meta_json)
    return meta_json


def is_nixpkgs_metadata(meta_json):
    """Return true if the given metadata describes nixpkgs."""
    try:
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


def _locked_obj_is_nixpkgs(node_name, locked_obj):
    try:
        if locked_obj.get("repo") == "nixpkgs":
            return True
        if node_name.startswith("nixpkgs") and locked_obj.get("type") == "path":
            return True
    except AttributeError:
        return False
    return False


def _input_node_names(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and value and isinstance(value[-1], str):
        # Lock-file override chains store the resolved input node as the last item.
        return [value[-1]]
    return []


def _get_flake_nixpkgs_obj(meta_json):
    try:
        nodes = meta_json["locks"]["nodes"]
        root_name = meta_json["locks"]["root"]
        root_inputs = nodes[root_name].get("inputs", {})
    except (KeyError, TypeError, AttributeError):
        return None

    for node_name in _input_node_names(root_inputs.get("nixpkgs")):
        try:
            return nodes[node_name]["locked"]
        except (KeyError, TypeError):
            continue

    candidates = []
    for node_name, node in nodes.items():
        try:
            locked_obj = node["locked"]
        except (KeyError, TypeError):
            continue
        if _locked_obj_is_nixpkgs(node_name, locked_obj):
            candidates.append(locked_obj)
    if len(candidates) == 1:
        return candidates[0]
    return None


def _get_flake_nixpkgs_val(meta_json, key):
    try:
        return _get_flake_nixpkgs_obj(meta_json)[key]
    except (KeyError, TypeError):
        return None


def _get_nixpkgs_flakeref_github(meta_json, *, log=LOG):
    owner = _get_flake_nixpkgs_val(meta_json, "owner")
    repo = _get_flake_nixpkgs_val(meta_json, "repo")
    rev = _get_flake_nixpkgs_val(meta_json, "rev")
    if None in [owner, repo, rev]:
        log.debug(
            "owner, repo, or rev not found: %s",
            _get_flake_nixpkgs_obj(meta_json),
        )
        return None
    return f"github:{owner}/{repo}?rev={rev}"


def _get_nixpkgs_flakeref_git(meta_json, *, log=LOG):
    url = _get_flake_nixpkgs_val(meta_json, "url")
    rev = _get_flake_nixpkgs_val(meta_json, "rev")
    ref = _get_flake_nixpkgs_val(meta_json, "ref")
    if None in [url, rev, ref]:
        log.debug("url, rev, or ref not found: %s", _get_flake_nixpkgs_obj(meta_json))
        return None
    return f"git+{url}?ref={ref}&rev={rev}"


def _get_nixpkgs_flakeref_path(meta_json, *, log=LOG):
    path = _get_flake_nixpkgs_val(meta_json, "path")
    if path is None:
        log.debug("path not found: %s", _get_flake_nixpkgs_obj(meta_json))
        return None
    return f"path:{path}"


def _get_nixpkgs_flakeref_tarball(meta_json, *, log=LOG):
    url = _get_flake_nixpkgs_val(meta_json, "url")
    if url is None:
        log.debug("url not found: %s", _get_flake_nixpkgs_obj(meta_json))
        return None
    return f"{url}"


def get_nixpkgs_flakeref(meta_json, *, log=LOG):
    """Given flake metadata, return the locked nixpkgs flakeref."""
    locked_type = _get_flake_nixpkgs_val(meta_json, "type")
    if locked_type == "github":
        return _get_nixpkgs_flakeref_github(meta_json, log=log)
    if locked_type == "git":
        return _get_nixpkgs_flakeref_git(meta_json, log=log)
    if locked_type == "path":
        return _get_nixpkgs_flakeref_path(meta_json, log=log)
    if locked_type == "tarball":
        return _get_nixpkgs_flakeref_tarball(meta_json, log=log)
    log.debug("Unsupported nixpkgs locked type: %s", locked_type)
    return None


def nixref_to_nixpkgs_path(
    flakeref,
    *,
    get_flake_metadata_fn=get_flake_metadata,
    log=LOG,
    log_spam=LOG_SPAM,
):
    """Return the nix store path of the nixpkgs pinned by ``flakeref``."""
    if not flakeref:
        return None
    log.info("Resolving nixpkgs path for '%s'", flakeref)
    log.debug("Finding meta-info for nixpkgs pinned in nixref: %s", flakeref)
    match = re.match(r"([^#]+)#", flakeref)
    if match:
        flakeref = match.group(1)
        log.debug("Stripped target specifier: %s", flakeref)
    meta_json = get_flake_metadata_fn(flakeref)
    if not is_nixpkgs_metadata(meta_json):
        log.debug("non-nixpkgs flakeref: %s", flakeref)
        nixpkgs_flakeref = get_nixpkgs_flakeref(meta_json, log=log)
        if not nixpkgs_flakeref:
            log.warning("Failed parsing locked nixpkgs: %s", flakeref)
            return None
        log.log(log_spam, "using nixpkgs_flakeref: %s", nixpkgs_flakeref)
        meta_json = get_flake_metadata_fn(nixpkgs_flakeref)
        if not is_nixpkgs_metadata(meta_json):
            log.warning("Failed reading nixpkgs metadata: %s", flakeref)
            return None
    return pathlib.Path(meta_json["path"]).absolute()
