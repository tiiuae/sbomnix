# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for provenance dependency resolution."""

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from common.log import LOG, LOG_VERBOSE
from common.nix_utils import parse_nix_derivation_show
from common.proc import exec_cmd, nix_cmd
from provenance.digests import normalize_digest, output_digest
from provenance.path_info import query_path_hashes, query_path_info
from provenance.subjects import output_path

HookFn = Callable[..., Any]


@dataclass
class DependencyHooks:
    """Injectable helpers used by provenance dependency resolution."""

    exec_cmd_fn: HookFn = exec_cmd
    query_path_hashes_fn: HookFn = field(default_factory=lambda: query_path_hashes)
    parse_nix_derivation_show_fn: HookFn = parse_nix_derivation_show
    normalize_digest_fn: HookFn = normalize_digest
    output_digest_fn: HookFn = output_digest
    output_path_fn: HookFn = output_path
    log: logging.Logger = LOG


def derivation_outputs_by_path(infos, hooks=None):
    """Index derivation info by absolute output path."""
    hooks = DependencyHooks() if hooks is None else hooks
    outputs_by_path = {}
    for info in infos.values():
        if not isinstance(info, dict):
            continue
        outputs = info.get("outputs")
        if not isinstance(outputs, dict):
            continue
        env = info.get("env")
        for name, output in outputs.items():
            resolved_output_path = hooks.output_path_fn(name, output, env)
            if resolved_output_path:
                outputs_by_path[resolved_output_path] = (info, output)
    return outputs_by_path


def dependency_paths(drv_path, recursive=False, outputs_by_path=None, hooks=None):
    """Return dependency store paths from structured path-info data."""
    hooks = DependencyHooks() if hooks is None else hooks
    path_infos = query_path_info(
        [drv_path],
        exec_cmd_fn=hooks.exec_cmd_fn,
        recursive=recursive,
    )
    if path_infos is None:
        return []
    if recursive:
        paths = list(path_infos)
        for path in outputs_by_path or ():
            if path not in path_infos:
                paths.append(path)
        return paths

    drv_info = path_infos.get(drv_path)
    if drv_info is None and path_infos:
        drv_info = next(iter(path_infos.values()))
    if not drv_info:
        return []
    references = drv_info.get("references", [])
    if not isinstance(references, list):
        return []
    return [path for path in references if isinstance(path, str)]


def dependency_package(drv, output_hash, infos, outputs_by_path, hooks=None):
    """Create a dependency package entry with a normalized digest."""
    hooks = DependencyHooks() if hooks is None else hooks
    info = infos.get(drv)
    output_info = outputs_by_path.get(drv)
    if output_info:
        info = output_info[0]
    digest = hooks.output_digest_fn(output_info[1]) if output_info else None
    if digest is None:
        digest = hooks.normalize_digest_fn(output_hash)
    if digest is None and ":" in output_hash:
        hash_type, hash_value = output_hash.split(":", 1)
        hooks.log.warning(
            "Falling back to non-normalized digest for dependency '%s': %s",
            drv,
            output_hash,
        )
        digest = {hash_type: hash_value}
    if digest is None:
        hooks.log.warning("Cannot determine digest for dependency '%s'", drv)
        return None

    package = {
        "name": drv.split("-", 1)[-1].removesuffix(".drv"),
        "uri": drv,
        "digest": digest,
    }

    if info:
        package["name"] = info["name"]
        if version := info["env"].get("version"):
            package["annotations"] = {"version": version}
    return package


def get_dependencies(drv_path, recursive=False, hooks=None):
    """Get dependencies of derivation and parse them into ResourceDescriptors."""
    hooks = DependencyHooks() if hooks is None else hooks

    hooks.log.log(
        LOG_VERBOSE,
        "Querying derivation dependencies %s",
        "recursively" if recursive else "",
    )

    infos = hooks.parse_nix_derivation_show_fn(
        hooks.exec_cmd_fn(nix_cmd("derivation", "show", "-r", drv_path)).stdout,
        store_path_hint=drv_path,
    )
    outputs_by_path = derivation_outputs_by_path(infos, hooks=hooks)
    references = dependency_paths(
        drv_path,
        recursive=recursive,
        outputs_by_path=outputs_by_path,
        hooks=hooks,
    )
    hashes = hooks.query_path_hashes_fn(references, exec_cmd_fn=hooks.exec_cmd_fn)

    dependencies = []
    for drv, output_hash in zip(references, hashes, strict=True):
        hooks.log.debug("Creating dependency entry for %s", drv)
        package = dependency_package(
            drv,
            output_hash,
            infos,
            outputs_by_path,
            hooks=hooks,
        )
        if package is not None:
            dependencies.append(package)

    return dependencies
