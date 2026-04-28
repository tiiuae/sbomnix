#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""SBOM component dataframe helpers."""

import pandas as pd

from common.log import LOG
from sbomnix.cpe import CPE
from sbomnix.derivation import load_many


def recursive_derivations_to_dataframe(paths, derivations, include_cpe=True):
    """Return component rows from an already-loaded derivation closure."""
    drvs = []
    for path in sorted(paths):
        drv = derivations.get(path)
        if not drv:
            LOG.debug("Recursive buildtime closure missing path: %s", path)
            continue
        drvs.append(drv)
    return derivations_to_dataframe(drvs, include_cpe=include_cpe)


def runtime_derivations_to_dataframe(paths, output_paths_by_drv, include_cpe=True):
    """Return component rows from runtime output-to-deriver mappings."""
    filtered_outputs_by_drv = filter_runtime_outputs_by_drv(
        paths,
        output_paths_by_drv,
    )
    derivations = load_many(
        sorted(filtered_outputs_by_drv),
        output_paths_by_drv=filtered_outputs_by_drv,
    ).values()
    return derivations_to_dataframe(derivations, include_cpe=include_cpe)


def derivations_to_dataframe(derivations, include_cpe=True):
    """Return component rows for loaded derivations."""
    cpe_generator = CPE(include_cpe=include_cpe)
    drv_dicts = []
    for drv in derivations:
        drv.set_cpe(cpe_generator)
        drv_dicts.append(drv.to_dict())
    return pd.DataFrame.from_records(drv_dicts)


def filter_runtime_outputs_by_drv(paths, output_paths_by_drv):
    """Filter runtime output mappings to the selected component paths."""
    selected_paths = set(paths)
    filtered_outputs_by_drv = {}
    for drv_path, output_paths in output_paths_by_drv.items():
        filtered_output_paths = set(output_paths) & selected_paths
        if filtered_output_paths:
            filtered_outputs_by_drv[drv_path] = filtered_output_paths
    return filtered_outputs_by_drv
