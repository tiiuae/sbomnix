# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Execution pipeline helpers for ``nix_outdated``."""

import logging
from dataclasses import dataclass

import pandas as pd

from common.df import df_log
from common.log import LOG, LOG_SPAM
from nixupdate.nix_visualize import nix_visualize_csv_to_df, run_nix_visualize
from repology.adapter import RepologyAdapter, RepologyQuery
from sbomnix.cli_utils import generate_temp_sbom


@dataclass
class OutdatedScanData:
    """Collected intermediate dataframes used by ``nix_outdated``."""

    repology: pd.DataFrame
    nix_visualize: pd.DataFrame | None = None


def query_repology(sbompath, *, adapter=None, log=LOG):
    """Query Repology package/version data for a generated SBOM."""
    log.info("Querying repology")
    if adapter is None:
        adapter = RepologyAdapter()
    return adapter.query(
        RepologyQuery(
            repository="nix_unstable",
            sbom_cdx=sbompath,
        )
    )


@dataclass
class OutdatedScanHooks:
    """Injectable helpers used by ``collect_outdated_scan_data``."""

    query_repology: object = query_repology
    generate_temp_sbom: object = generate_temp_sbom
    run_nix_visualize: object = run_nix_visualize
    parse_nix_visualize: object = nix_visualize_csv_to_df


def collect_outdated_scan_data(
    target_path,
    buildtime,
    hooks=None,
):
    """Collect Repology and ``nix-visualize`` inputs for reporting."""
    hooks = OutdatedScanHooks() if hooks is None else hooks
    dtype = "buildtime" if buildtime else "runtime"
    LOG.info("Checking %s dependencies referenced by '%s'", dtype, target_path)
    df_nix_visualize = None
    sbom_artifact = hooks.generate_temp_sbom(
        target_path,
        buildtime,
        prefix="nixdeps_",
        cdx_suffix=".cdx.json",
    )
    try:
        sbom_path = sbom_artifact.cdx_path
        LOG.debug("Using SBOM '%s'", sbom_path)
        df_repology = hooks.query_repology(sbom_path)
    finally:
        if LOG.level > logging.DEBUG:
            sbom_artifact.cleanup()
    df_log(df_repology, LOG_SPAM)

    if buildtime:
        LOG.info("Not running nix-visualize due to '--buildtime' argument")
    else:
        nix_visualize_out = hooks.run_nix_visualize(target_path)
        LOG.debug("Using nix-visualize out: '%s'", nix_visualize_out)
        try:
            df_nix_visualize = hooks.parse_nix_visualize(nix_visualize_out)
            df_log(df_nix_visualize, LOG_SPAM)
        finally:
            if LOG.level > logging.DEBUG:
                nix_visualize_out.unlink(missing_ok=True)

    df_log(df_repology, logging.DEBUG)
    df_log(df_nix_visualize, logging.DEBUG)
    return OutdatedScanData(
        repology=df_repology,
        nix_visualize=df_nix_visualize,
    )
