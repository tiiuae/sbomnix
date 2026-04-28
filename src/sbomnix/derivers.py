# From: https://github.com/flyingcircusio/vulnix/blob/1.10.1/LICENSE:
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Flying Circus Internet Operations GmbH

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

"""Deriver lookup helpers for Nix store paths."""

import os

from common.log import LOG, LOG_SPAM
from common.nix_utils import parse_nix_derivation_show
from common.proc import exec_cmd, nix_cmd


def is_loadable_deriver_path(path):
    """Return whether path names an existing Nix derivation file."""
    return (
        isinstance(path, str)
        and path != "unknown-deriver"
        and path.endswith(".drv")
        and os.path.exists(path)
    )


def find_deriver(path):
    """Return drv path for the given nix store artifact path."""
    LOG.log(LOG_SPAM, path)
    if path.endswith(".drv"):
        return path
    cmd = nix_cmd("derivation", "show", path)
    ret = exec_cmd(cmd, raise_on_error=False, log_error=False)
    if not ret:
        LOG.log(LOG_SPAM, "Deriver not found for '%s'", path)
        return None
    qvd_json_keys = list(
        parse_nix_derivation_show(ret.stdout, store_path_hint=path).keys()
    )
    if not qvd_json_keys:
        LOG.log(LOG_SPAM, "Not qvd_deriver for '%s'", path)
        return None
    qvd_deriver = qvd_json_keys[0]
    LOG.log(LOG_SPAM, "qvd_deriver: %s", qvd_deriver)
    if is_loadable_deriver_path(qvd_deriver):
        return qvd_deriver

    qpi_deriver = exec_cmd(["nix-store", "-qd", path]).stdout.strip()
    LOG.log(LOG_SPAM, "qpi_deriver: %s", qpi_deriver)
    if is_loadable_deriver_path(qpi_deriver):
        return qpi_deriver

    error = ""
    if qpi_deriver and qpi_deriver != "unknown-deriver":
        error += f"Deriver `{qpi_deriver}` does not exist.  "
    if qvd_deriver and qvd_deriver != qpi_deriver:
        error += f"Deriver `{qvd_deriver}` does not exist.  "
    if error:
        raise RuntimeError(error + f"Couldn't find deriver for path `{path}`")
    raise RuntimeError(
        "Cannot determine deriver. Is this really a path into the nix store?",
        path,
    )


def find_derivers(paths, batch_size=500):
    """Return drv paths for many store artifacts, batching `nix-store -qd`."""
    resolved = {}
    non_drv_paths = []
    for path in paths:
        if path.endswith(".drv"):
            resolved[path] = path
        else:
            non_drv_paths.append(path)
    if not non_drv_paths:
        return resolved
    for start in range(0, len(non_drv_paths), batch_size):
        batch = non_drv_paths[start : start + batch_size]
        ret = exec_cmd(
            ["nix-store", "-qd", *batch], raise_on_error=False, log_error=False
        )
        if ret:
            lines = ret.stdout.splitlines()
            if len(lines) == len(batch):
                for path, drv_path in zip(batch, lines, strict=True):
                    if is_loadable_deriver_path(drv_path):
                        resolved[path] = drv_path
                        continue
                    resolved[path] = find_deriver(path)
                continue
            LOG.debug(
                "nix-store -qd returned %d lines for %d paths; "
                "falling back to per-path lookup",
                len(lines),
                len(batch),
            )
        for path in batch:
            resolved[path] = find_deriver(path)
    return resolved
