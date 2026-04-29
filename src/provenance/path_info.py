# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Structured Nix path-info helpers for provenance generation."""

import errno
import subprocess

from common.errors import InvalidNixJsonError, NixCommandError
from common.nix_utils import (
    NIX_PATH_INFO_JSON,
    load_nix_json,
    nix_path_info_nar_hash,
    normalize_nix_path_info,
)
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
    cmd = nix_cmd(
        "path-info",
        "--json",
        "--json-format",
        "1",
        *recursive_args,
        *paths,
    )
    try:
        ret = exec_cmd_fn(cmd, raise_on_error=raise_on_error)
    except subprocess.CalledProcessError as error:
        raise NixCommandError(
            cmd,
            stderr=error.stderr,
            stdout=error.stdout,
        ) from None
    if ret is None:
        return None
    return normalize_nix_path_info(load_nix_json(ret.stdout, NIX_PATH_INFO_JSON))


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
        raise InvalidNixJsonError(
            NIX_PATH_INFO_JSON,
            f"missing path-info record for `{path}`",
        )
    return nix_path_info_nar_hash(info, path)
