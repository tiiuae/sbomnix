#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for nixgraph store-path discovery."""

from common.errors import MissingNixDeriverError
from common.log import LOG
from sbomnix.derivers import find_deriver


def find_deriver_path(nix_path, *, find_deriver_fn=find_deriver, log=LOG):
    """Resolve a nix store path or output path to its deriver."""
    drv_path = find_deriver_fn(nix_path)
    if not drv_path:
        raise MissingNixDeriverError(nix_path)
    log.debug("nix_drv: %s", drv_path)
    return drv_path
