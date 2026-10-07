#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Runtime closure helpers based on structured Nix path-info JSON."""

import subprocess
from dataclasses import dataclass

import pandas as pd

from common import columns as cols
from common.errors import NixCommandError
from common.nix_utils import (
    NIX_PATH_INFO_JSON,
    load_nix_json,
    nix_path_info_deriver,
    nix_path_info_references,
    normalize_nix_path_info,
    parse_nix_derivation_show,
)
from common.proc import exec_cmd, nix_cmd
from sbomnix.closure import (
    dependency_rows_to_dataframe,
    store_path_label,
)
from sbomnix.derivation import derivation_output_paths


@dataclass(frozen=True)
class RuntimeClosure:
    """Runtime dependency edges and output-to-deriver mapping."""

    df_deps: pd.DataFrame
    output_paths_by_drv: dict[str, set[str]]


def load_runtime_closure(path, derivers=None):
    """Load runtime closure information using ``nix path-info`` JSON."""
    cmd = nix_cmd(
        "path-info",
        "--json",
        "--json-format",
        "1",
        "--recursive",
        path,
    )
    try:
        ret = exec_cmd(cmd)
    except subprocess.CalledProcessError as error:
        raise NixCommandError(
            cmd,
            stderr=error.stderr,
            stdout=error.stdout,
        ) from None
    return runtime_closure_from_path_info(
        load_nix_json(ret.stdout, NIX_PATH_INFO_JSON), derivers
    )


def target_output_derivers(drv_path):
    """Return {output path: derivation} for the build closure of ``drv_path``.

    When several derivations in the closure produce the same output,
    the lowest store path wins, so the choice is stable.
    """
    cmd = nix_cmd("derivation", "show", "--recursive", drv_path)
    try:
        ret = exec_cmd(cmd)
    except subprocess.CalledProcessError as error:
        raise NixCommandError(
            cmd,
            stderr=error.stderr,
            stdout=error.stdout,
        ) from None
    derivers = {}
    drv_infos = parse_nix_derivation_show(ret.stdout, store_path_hint=drv_path)
    for drv, drv_info in sorted(drv_infos.items()):
        for output_path in derivation_output_paths(drv_info):
            derivers.setdefault(output_path, drv)
    return derivers


def runtime_closure_from_path_info(path_info, derivers=None):
    """Return runtime closure data from parsed ``nix path-info`` JSON."""
    derivers = {} if derivers is None else derivers
    rows = []
    output_paths_by_drv = {}
    for target_path, info in normalize_nix_path_info(path_info).items():
        if info is None:
            continue
        deriver = derivers.get(target_path) or nix_path_info_deriver(info, target_path)
        if deriver:
            output_paths_by_drv.setdefault(deriver, set()).add(target_path)
        for src_path in nix_path_info_references(info, target_path):
            if src_path == target_path:
                continue
            rows.append(
                {
                    cols.SRC_PATH: src_path,
                    "src_pname": store_path_label(src_path),
                    cols.TARGET_PATH: target_path,
                    "target_pname": store_path_label(target_path),
                }
            )
    return RuntimeClosure(
        df_deps=dependency_rows_to_dataframe(rows),
        output_paths_by_drv=output_paths_by_drv,
    )
