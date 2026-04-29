# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Structured Nix path-info helpers for provenance generation."""

import errno
import json

from common.proc import exec_cmd, nix_cmd


def query_path_info(
    paths,
    *,
    exec_cmd_fn=exec_cmd,
    recursive=False,
    raise_on_error=True,
):
    """Return structured path-info records indexed by store path."""
    if not paths:
        return {}
    recursive_args = ["--recursive"] if recursive else []
    ret = exec_cmd_fn(
        nix_cmd(
            "path-info",
            "--json",
            "--json-format",
            "1",
            *recursive_args,
            *paths,
        ),
        raise_on_error=raise_on_error,
    )
    if ret is None:
        return None
    return normalize_path_info(json.loads(ret.stdout))


def normalize_path_info(path_info):
    """Normalize Nix path-info JSON to a path-indexed dictionary."""
    if isinstance(path_info, dict):
        return {
            path: info
            for path, info in path_info.items()
            if isinstance(path, str) and isinstance(info, dict)
        }
    if isinstance(path_info, list):
        normalized = {}
        for info in path_info:
            if not isinstance(info, dict):
                continue
            path = info.get("path") or info.get("storePath")
            if isinstance(path, str):
                normalized[path] = info
        return normalized
    return {}


def query_path_hashes(paths, *, exec_cmd_fn=exec_cmd):
    """Query NAR hashes for paths, splitting requests that exceed argv limits."""
    paths = list(paths)
    if not paths:
        return []
    try:
        path_infos = query_path_info(paths, exec_cmd_fn=exec_cmd_fn)
    except OSError as error:
        if error.errno != errno.E2BIG or len(paths) == 1:
            raise
        midpoint = len(paths) // 2
        return query_path_hashes(
            paths[:midpoint],
            exec_cmd_fn=exec_cmd_fn,
        ) + query_path_hashes(
            paths[midpoint:],
            exec_cmd_fn=exec_cmd_fn,
        )
    if path_infos is None:
        return []
    return [nar_hash_for_path(path_infos, path) for path in paths]


def nar_hash_for_path(path_infos, path):
    """Return the NAR hash for one path-info record."""
    info = path_infos.get(path)
    if info is None:
        raise RuntimeError(f"Missing path-info for '{path}'")
    nar_hash = info.get("narHash")
    if not isinstance(nar_hash, str) or not nar_hash:
        raise RuntimeError(f"Missing narHash in path-info for '{path}'")
    return nar_hash
