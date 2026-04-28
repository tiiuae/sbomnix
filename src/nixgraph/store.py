#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for nixgraph store-path discovery and nix-store execution."""

import re

from common.errors import MissingNixDeriverError, MissingNixOutPathError
from common.log import LOG
from common.proc import exec_cmd
from sbomnix.derivers import find_deriver


def get_nix_store_path(nix_path, log=LOG):
    """Return nix store path given derivation or out-path."""
    store_path = "/nix/store/"
    re_nix_store_path = re.compile(r"(?P<store_path>/.+/)[0-9a-z]{32}-")
    store_path_match = re_nix_store_path.match(nix_path)
    if store_path_match:
        store_path = store_path_match.group("store_path")
    log.debug("Using nix store path: '%s'", store_path)
    return store_path


def find_deriver_path(nix_path, *, find_deriver_fn=find_deriver, log=LOG):
    """Resolve a nix store path or output path to its deriver."""
    drv_path = find_deriver_fn(nix_path)
    if not drv_path:
        raise MissingNixDeriverError(nix_path)
    log.debug("nix_drv: %s", drv_path)
    return drv_path


def find_output_path(nix_path, *, exec_cmd_fn=exec_cmd, log=LOG):
    """Resolve derivation output path from a derivation path."""
    out_path = exec_cmd_fn(
        [
            "nix-store",
            "--query",
            "--binding",
            "out",
            nix_path,
        ]
    ).stdout.strip()
    if not out_path:
        raise MissingNixOutPathError(nix_path)
    log.debug("out_path: %s", out_path)
    return out_path


def runtime_query_output(drv_path, *, exec_cmd_fn=exec_cmd):
    """Return runtime dependency graph text for a derivation."""
    return exec_cmd_fn(["nix-store", "-u", "-f", "-q", "--graph", drv_path]).stdout


def buildtime_query_output(drv_path, *, exec_cmd_fn=exec_cmd):
    """Return buildtime dependency graph text for a derivation."""
    return exec_cmd_fn(["nix-store", "-q", "--graph", drv_path]).stdout
