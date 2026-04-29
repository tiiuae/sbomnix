# From: https://github.com/flyingcircusio/vulnix/blob/1.10.1/LICENSE:
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Flying Circus Internet Operations GmbH

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

"""Deriver lookup helpers for Nix store paths."""

import os

from common.errors import MissingNixDeriverError, SbomnixError
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

    if qvd_deriver and qvd_deriver != "unknown-deriver":
        raise RuntimeError(
            f"Deriver `{qvd_deriver}` does not exist.  "
            f"Couldn't find deriver for path `{path}`"
        )
    raise RuntimeError(
        "Cannot determine deriver. Is this really a path into the nix store?",
        path,
    )


def require_deriver(path, *, find_deriver_fn=find_deriver, log=LOG):
    """Return the deriver for ``path`` or raise a typed error."""
    try:
        drv_path = find_deriver_fn(path)
    except SbomnixError:
        raise
    except RuntimeError as error:
        raise MissingNixDeriverError(path) from error
    if not drv_path:
        raise MissingNixDeriverError(path)
    log.debug("nix_drv: %s", drv_path)
    return drv_path
