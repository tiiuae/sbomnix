#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Runtime closure helpers based on structured Nix path-info JSON."""

import json
from dataclasses import dataclass

import pandas as pd

from common import columns as cols
from common.proc import exec_cmd, nix_cmd
from sbomnix.closure import (
    dependency_rows_to_dataframe,
    store_path_label,
)


@dataclass(frozen=True)
class RuntimeClosure:
    """Runtime dependency edges and output-to-deriver mapping."""

    df_deps: pd.DataFrame
    output_paths_by_drv: dict[str, set[str]]


def load_runtime_closure(path):
    """Load runtime closure information using ``nix path-info`` JSON."""
    ret = exec_cmd(
        nix_cmd(
            "path-info",
            "--json",
            "--json-format",
            "1",
            "--recursive",
            path,
        )
    )
    return runtime_closure_from_path_info(json.loads(ret.stdout))


def runtime_closure_from_path_info(path_info):
    """Return runtime closure data from parsed ``nix path-info`` JSON."""
    rows = []
    output_paths_by_drv = {}
    for target_path, info in _iter_path_info(path_info):
        deriver = info.get("deriver")
        if isinstance(deriver, str) and deriver:
            output_paths_by_drv.setdefault(deriver, set()).add(target_path)
        for src_path in _iter_references(info):
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


def _iter_path_info(path_info):
    if isinstance(path_info, dict):
        for path, info in path_info.items():
            if isinstance(info, dict):
                yield path, info
    elif isinstance(path_info, list):
        for info in path_info:
            if not isinstance(info, dict):
                continue
            # Nix path-info list payloads use "path"; accept "storePath" for
            # callers that pass already-normalized store path records.
            path = info.get("path") or info.get("storePath")
            if isinstance(path, str):
                yield path, info


def _iter_references(info):
    references = info.get("references", [])
    if not isinstance(references, list):
        return
    for reference in references:
        if isinstance(reference, str) and reference:
            yield reference
