#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""SBOM builder orchestration."""

import logging
import uuid

import numpy as np

from common import columns as cols
from common.df import df_to_csv_file
from common.log import LOG, is_debug_enabled
from sbomnix.closure import (
    DEPENDENCY_COLUMNS,
    dependencies_to_depth,
    dependency_paths,
    derivation_dependencies_df,
)
from sbomnix.components import (
    recursive_derivations_to_dataframe,
    runtime_derivations_to_dataframe,
)
from sbomnix.dependency_index import build_dependency_index
from sbomnix.derivation import load_recursive
from sbomnix.derivers import find_deriver, is_loadable_deriver_path
from sbomnix.exporters import build_cdx_document, build_spdx_document, write_json
from sbomnix.meta import Meta, NixpkgsMetaSource
from sbomnix.runtime import (
    load_runtime_closure,
)
from sbomnix.vuln_enrichment import enrich_cdx_with_vulnerabilities

###############################################################################

# Namespace UUID (a UUIDv4) for stable UUIDv5 identifiers.
# See RFC9562, *6.6.  Namespace ID Usage and Allocation*.
SBOMNIX_UUID_NAMESPACE = uuid.UUID("136af32e-0d0e-48bc-912c-31b26af294b9")


def _runtime_output_paths_by_load_path(output_paths_by_drv):
    output_paths_by_load_path = {}
    for drv_path, output_paths in output_paths_by_drv.items():
        if is_loadable_deriver_path(drv_path):
            output_paths_by_load_path.setdefault(drv_path, set()).update(output_paths)
            continue
        for output_path in output_paths:
            output_paths_by_load_path.setdefault(output_path, set()).add(output_path)
    return output_paths_by_load_path


def _mapped_runtime_output_paths(output_paths_by_load_path):
    if not output_paths_by_load_path:
        return set()
    return set().union(*output_paths_by_load_path.values())


class SbomBuilder:
    """Generate SBOMs in various formats."""

    def __init__(  # noqa: PLR0913, PLR0917
        self,
        nix_path,
        buildtime=False,
        depth=None,
        flakeref=None,
        original_ref=None,
        meta_nixpkgs=None,
        impure=False,
        include_meta=True,
        include_vulns=False,
        include_cpe=True,
    ):
        # self.uid specifies the attribute that identifies SBOM components.
        # See the column names in
        # self.df_sbomdb (sbom.csv) for a list of all components' attributes.
        self.uid = cols.STORE_PATH
        self.nix_path = nix_path
        self.buildtime = buildtime
        self.target_deriver = find_deriver(nix_path)
        if self.target_deriver is None:
            raise RuntimeError(f"Failed finding deriver for '{nix_path}'")
        self._recursive_buildtime_derivations = None
        self._runtime_output_paths_by_drv = None
        self.df_deps = None
        self.depth = depth
        self._init_dependencies(nix_path)
        self.df_sbomdb = None
        self.df_sbomdb_outputs_exploded = None
        self.dependency_index = None
        self.flakeref = flakeref
        self.original_ref = original_ref
        self.meta_nixpkgs = meta_nixpkgs
        self.impure = impure
        self.meta = None
        # "disabled" records explicit opt-out; "none" means auto-selection
        # found no source.
        self.nixpkgs_meta_source = NixpkgsMetaSource(method="disabled")
        self.include_cpe = include_cpe
        self._init_components(include_meta)
        self.include_vulns = include_vulns
        # Use a random UUID as the serial number when any data source that is
        # not strictly coming from the target_deriver is used
        if include_vulns or include_meta or include_cpe:
            LOG.verbose("Using random UUIDv4")
            self.uuid = uuid.uuid4()
        else:
            LOG.verbose("Using stable UUIDv5 for '%s'", self.target_deriver)
            # This uses a UUIDv5, which uses the deriver's store path as its input,
            # resulting in a stable UUID across runs, depending on the SBOM's subject.
            self.uuid = uuid.uuid5(SBOMNIX_UUID_NAMESPACE, self.target_deriver)
        self.sbom_type = "runtime_and_buildtime"
        if not self.buildtime:
            self.sbom_type = "runtime_only"

    def _init_dependencies(self, nix_path):
        """Initialize dependencies (df_deps)"""
        if self.buildtime:
            self._init_recursive_buildtime_dependencies()
            return
        self._init_runtime_path_info_dependencies(nix_path)

    def _init_recursive_buildtime_dependencies(self):
        """Initialize build-time dependencies from recursive derivation JSON."""
        derivations, drv_infos = load_recursive(self.target_deriver)
        self._recursive_buildtime_derivations = derivations
        self.df_deps = derivation_dependencies_df(drv_infos)
        if self.depth:
            self.df_deps = self._filter_dependencies_to_depth(
                self.df_deps,
                self.target_deriver,
                self.depth,
            )

    def _init_runtime_path_info_dependencies(self, nix_path):
        """Initialize runtime dependencies from structured path-info JSON."""
        runtime_closure = load_runtime_closure(nix_path)
        output_paths_by_load_path = _runtime_output_paths_by_load_path(
            runtime_closure.output_paths_by_drv
        )
        mapped_paths = _mapped_runtime_output_paths(output_paths_by_load_path)
        if nix_path not in mapped_paths:
            output_paths_by_load_path.setdefault(self.target_deriver, set()).add(
                nix_path
            )
            mapped_paths.add(nix_path)
        graph_only_paths = dependency_paths(runtime_closure.df_deps) - mapped_paths
        if graph_only_paths:
            LOG.debug(
                "Runtime path-info references graph-only paths: %s",
                sorted(graph_only_paths),
            )
        self._runtime_output_paths_by_drv = output_paths_by_load_path
        self.df_deps = runtime_closure.df_deps
        if self.depth:
            self.df_deps = self._filter_dependencies_to_depth(
                self.df_deps,
                nix_path,
                self.depth,
            )

    def _init_runtime_components(self, paths):
        assert self._runtime_output_paths_by_drv is not None
        return runtime_derivations_to_dataframe(
            paths,
            self._runtime_output_paths_by_drv,
            include_cpe=self.include_cpe,
        )

    def _filter_dependencies_to_depth(
        self,
        df_deps,
        start_path,
        depth,
        columns=DEPENDENCY_COLUMNS,
    ):
        """Return dependency rows reachable from ``start_path`` up to ``depth``."""
        LOG.debug("Reading dependencies until depth=%s", depth)
        return dependencies_to_depth(df_deps, start_path, depth, columns=columns)

    def _init_components(self, include_meta):
        """Initialize the SBOM component dataframe."""
        paths = self._sbom_component_paths()
        # Populate store based on the dependencies
        if self._recursive_buildtime_derivations is not None:
            self.df_sbomdb = recursive_derivations_to_dataframe(
                paths,
                self._recursive_buildtime_derivations,
                include_cpe=self.include_cpe,
            )
        elif self._runtime_output_paths_by_drv is not None:
            self.df_sbomdb = self._init_runtime_components(paths)
        else:
            raise RuntimeError("Structured dependency metadata was not initialized")
        # Join with meta information
        if include_meta:
            self._join_meta()
        # Clean, drop duplicates, sort
        self.df_sbomdb.replace(np.nan, "", regex=True, inplace=True)
        self.df_sbomdb.drop_duplicates(subset=[self.uid], keep="first", inplace=True)
        self.df_sbomdb.sort_values(by=[cols.NAME, self.uid], inplace=True)
        self.df_sbomdb_outputs_exploded = self.df_sbomdb.explode(cols.OUTPUTS)
        self._init_dependency_index()

    def _sbom_component_paths(self):
        if self.df_deps is None or self.df_deps.empty:
            if self._runtime_output_paths_by_drv is not None:
                return set().union(*self._runtime_output_paths_by_drv.values())
            # No dependencies, so the only component in the sbom
            # will be the target itself.
            return set([self.target_deriver])
        return dependency_paths(self.df_deps)

    def _init_dependency_index(self):
        """Build indexed dependency lookups used during export."""
        self.dependency_index = build_dependency_index(
            self.df_deps,
            self.df_sbomdb,
            self.df_sbomdb_outputs_exploded,
            uid=self.uid,
        )

    def _join_meta(self):
        """Join component rows with nixpkgs metadata."""
        assert self.df_sbomdb is not None
        self.meta = Meta()
        df_meta, source = self.meta.get_nixpkgs_meta_with_source(
            target_path=self.nix_path,
            flakeref=self.flakeref,
            original_ref=self.original_ref,
            explicit_nixpkgs=self.meta_nixpkgs,
            impure=self.impure,
        )
        self.nixpkgs_meta_source = source
        if df_meta is None or df_meta.empty:
            if source.message:
                LOG.info("%s", source.message)
            if source.path:
                LOG.warning(
                    "Failed reading nix meta information: "
                    "SBOM will include only minimum set of attributes"
                )
            else:
                LOG.info(
                    "Skipping nix meta information: "
                    "SBOM will include only minimum set of attributes"
                )
            return
        if is_debug_enabled():
            df_to_csv_file(df_meta, "meta.csv")
        # Join based on package name including the version number
        self.df_sbomdb = self.df_sbomdb.merge(
            df_meta,
            how="left",
            left_on=[cols.NAME],
            right_on=[cols.NAME],
            suffixes=("", "_meta"),
        )

    def lookup_dependencies(self, drv, uid=cols.STORE_PATH):
        """Return indexed dependency values for one SBOM component."""
        dependency_index = getattr(self, "dependency_index", None)
        if dependency_index is None:
            return None
        return dependency_index.lookup(drv, uid=uid)

    def to_cdx_data(self):
        """Return the SBOM as a CycloneDX document."""
        return build_cdx_document(self)

    def enrich_cdx_with_vulnerabilities(self, cdx):
        """Add vulnerability scan results to an existing CycloneDX document."""
        return enrich_cdx_with_vulnerabilities(self, cdx)

    def to_spdx_data(self):
        """Return the SBOM as an SPDX document."""
        return build_spdx_document(self)

    def write_json(self, pathname, data, printinfo=False):
        """Write a JSON document to a file."""
        write_json(pathname, data, printinfo=printinfo)

    def to_cdx(self, cdx_path, printinfo=True):
        """Export SBOM components to a CycloneDX JSON file."""
        cdx = self.to_cdx_data()
        self.write_json(cdx_path, cdx, printinfo)

    def to_spdx(self, spdx_path, printinfo=True):
        """Export SBOM components to an SPDX JSON file."""
        spdx = self.to_spdx_data()
        self.write_json(spdx_path, spdx, printinfo)

    def to_csv(self, csv_path, loglevel=logging.INFO):
        """Export SBOM components to a CSV file."""
        df_to_csv_file(self.df_sbomdb, csv_path, loglevel)
