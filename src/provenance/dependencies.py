# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for provenance dependency resolution."""

import errno
from dataclasses import dataclass

from common.log import LOG
from common.nix_utils import parse_nix_derivation_show
from common.proc import exec_cmd
from provenance.digests import normalize_digest, output_digest
from provenance.subjects import output_path


@dataclass
class DependencyHooks:
    """Injectable helpers used by provenance dependency resolution."""

    exec_cmd_fn: object = None
    query_store_hashes_fn: object = None
    parse_nix_derivation_show_fn: object = None
    normalize_digest_fn: object = None
    output_digest_fn: object = None
    output_path_fn: object = None
    log: object = LOG

    def __post_init__(self):
        if self.exec_cmd_fn is None:
            self.exec_cmd_fn = exec_cmd
        if self.query_store_hashes_fn is None:
            self.query_store_hashes_fn = query_store_hashes
        if self.parse_nix_derivation_show_fn is None:
            self.parse_nix_derivation_show_fn = parse_nix_derivation_show
        if self.normalize_digest_fn is None:
            self.normalize_digest_fn = normalize_digest
        if self.output_digest_fn is None:
            self.output_digest_fn = output_digest
        if self.output_path_fn is None:
            self.output_path_fn = output_path


def query_store_hashes(paths, hooks=None):
    """Query store hashes, splitting the request when argv exceeds OS limits."""
    hooks = DependencyHooks() if hooks is None else hooks
    if not paths:
        return []

    try:
        return hooks.exec_cmd_fn(
            ["nix-store", "--query", "--hash", *paths]
        ).stdout.split()
    except OSError as error:
        if error.errno != errno.E2BIG or len(paths) == 1:
            raise
        midpoint = len(paths) // 2
        return query_store_hashes(paths[:midpoint], hooks=hooks) + query_store_hashes(
            paths[midpoint:],
            hooks=hooks,
        )


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

    hooks.log.info(
        "Querying derivation dependencies %s",
        "recursively" if recursive else "",
    )

    depth = "--requisites" if recursive else "--references"
    references = hooks.exec_cmd_fn(
        ["nix-store", "--query", depth, "--include-outputs", drv_path]
    ).stdout.split()
    hashes = hooks.query_store_hashes_fn(references)
    infos = hooks.parse_nix_derivation_show_fn(
        hooks.exec_cmd_fn(["nix", "derivation", "show", "-r", drv_path]).stdout,
        store_path_hint=drv_path,
    )
    outputs_by_path = derivation_outputs_by_path(infos, hooks=hooks)

    dependencies = []
    for drv, output_hash in zip(references, hashes):
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
