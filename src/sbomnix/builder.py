#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""SBOM builder orchestration."""

import logging
import uuid
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd

from common import columns as cols
from common.df import df_to_csv_file
from common.errors import (
    MissingNixDerivationMetadataError,
    MissingNixDeriverError,
    SbomnixError,
)
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
from sbomnix.derivers import find_deriver, is_loadable_deriver_path, require_deriver
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


@dataclass(frozen=True)
class StructuredClosure:
    """Structured dependency data used to assemble an SBOM."""

    df_deps: pd.DataFrame
    recursive_buildtime_derivations: dict[str, Any] | None = None
    runtime_output_paths_by_load_path: dict[str, set[str]] | None = None


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
        self.target_deriver = self._resolve_target_deriver(nix_path)
        self.target_component_ref = None
        self._recursive_buildtime_derivations = None
        self._runtime_output_paths_by_load_path = None
        self.df_deps = None
        self.depth = depth
        self._structured_closure = self._load_structured_closure(nix_path)
        self._init_dependencies(self._structured_closure)
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
        target_component_ref = self._resolve_target_component_ref()
        self.target_component_ref = target_component_ref
        self.include_vulns = include_vulns
        # Use a random UUID as the serial number when any data source that is
        # not strictly coming from the resolved target component is used.
        if include_vulns or include_meta or include_cpe:
            LOG.verbose("Using random UUIDv4")
            self.uuid = uuid.uuid4()
        else:
            LOG.verbose("Using stable UUIDv5 for '%s'", target_component_ref)
            # This uses a UUIDv5, resulting in a stable UUID across runs for
            # the same SBOM subject.
            self.uuid = uuid.uuid5(SBOMNIX_UUID_NAMESPACE, target_component_ref)
        self.sbom_type = "runtime_and_buildtime"
        if not self.buildtime:
            self.sbom_type = "runtime_only"

    def _resolve_target_deriver(self, nix_path):
        if self.buildtime:
            return require_deriver(nix_path)
        try:
            return find_deriver(nix_path)
        except SbomnixError:
            raise
        except RuntimeError:
            LOG.debug(
                "Runtime target has no loadable deriver: %s",
                nix_path,
                exc_info=True,
            )
            return None

    def _load_structured_closure(self, nix_path):
        """Load structured dependency data for the configured SBOM type."""
        if self.buildtime:
            if self.target_deriver is None:
                raise MissingNixDeriverError(nix_path)
            return self._load_recursive_buildtime_closure()
        return self._load_runtime_path_info_closure(nix_path)

    def _init_dependencies(self, closure):
        """Initialize dependency attributes from loaded structured data."""
        self.df_deps = closure.df_deps
        self._recursive_buildtime_derivations = closure.recursive_buildtime_derivations
        self._runtime_output_paths_by_load_path = (
            closure.runtime_output_paths_by_load_path
        )

    def _load_recursive_buildtime_closure(self):
        """Load build-time dependencies from recursive derivation JSON."""
        if self.target_deriver is None:
            raise MissingNixDeriverError(self.nix_path)
        derivations, drv_infos = load_recursive(self.target_deriver)
        df_deps = derivation_dependencies_df(drv_infos)
        if self.depth:
            df_deps = self._filter_dependencies_to_depth(
                df_deps,
                self.target_deriver,
                self.depth,
            )
        return StructuredClosure(
            df_deps=df_deps,
            recursive_buildtime_derivations=derivations,
        )

    def _load_runtime_path_info_closure(self, nix_path):
        """Load runtime dependencies from structured path-info JSON."""
        runtime_closure = load_runtime_closure(nix_path)
        output_paths_by_load_path = _runtime_output_paths_by_load_path(
            runtime_closure.output_paths_by_drv
        )
        mapped_paths = _mapped_runtime_output_paths(output_paths_by_load_path)
        if nix_path not in mapped_paths:
            load_path = self.target_deriver or nix_path
            output_paths_by_load_path.setdefault(load_path, set()).add(nix_path)
            mapped_paths.add(nix_path)
        graph_only_paths = dependency_paths(runtime_closure.df_deps) - mapped_paths
        if graph_only_paths:
            LOG.debug(
                "Runtime path-info references graph-only paths: %s",
                sorted(graph_only_paths),
            )
        df_deps = runtime_closure.df_deps
        if self.depth:
            df_deps = self._filter_dependencies_to_depth(
                df_deps,
                nix_path,
                self.depth,
            )
        return StructuredClosure(
            df_deps=df_deps,
            runtime_output_paths_by_load_path=output_paths_by_load_path,
        )

    def _init_runtime_components(self, paths):
        if self._runtime_output_paths_by_load_path is None:
            raise AssertionError("Runtime output metadata was not initialized")
        df_components = runtime_derivations_to_dataframe(
            paths,
            self._runtime_output_paths_by_load_path,
            include_cpe=self.include_cpe,
        )
        if df_components.empty:
            raise MissingNixDerivationMetadataError(self.nix_path)
        return df_components

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
        elif self._runtime_output_paths_by_load_path is not None:
            self.df_sbomdb = self._init_runtime_components(paths)
        else:
            # _load_structured_closure always selects exactly one metadata source.
            raise AssertionError("Structured dependency metadata was not initialized")
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
            if self._runtime_output_paths_by_load_path is not None:
                return set().union(*self._runtime_output_paths_by_load_path.values())
            # No dependencies, so the only component in the sbom
            # will be the target itself.
            if self.target_deriver:
                return {self.target_deriver}
            return {self.nix_path}
        return dependency_paths(self.df_deps)

    def _resolve_target_component_ref(self) -> str:
        """Return the component reference that represents the SBOM subject."""
        if self.df_sbomdb is None:
            raise AssertionError("SBOM component metadata was not initialized")
        if self.target_deriver:
            df_target = self.df_sbomdb[
                self.df_sbomdb[cols.STORE_PATH] == self.target_deriver
            ]
            if not df_target.empty:
                return self.target_deriver
        for component in self.df_sbomdb.to_dict("records"):
            store_path = component.get(cols.STORE_PATH)
            if not isinstance(store_path, str):
                continue
            outputs = component.get(cols.OUTPUTS, [])
            if isinstance(outputs, str):
                outputs = [outputs]
            elif not isinstance(outputs, (list, tuple, set)):
                continue
            if self.nix_path in outputs:
                return store_path
        if self.target_deriver:
            return self.target_deriver
        raise MissingNixDerivationMetadataError(self.nix_path)

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
        if self.df_sbomdb is None:
            raise AssertionError("SBOM component metadata was not initialized")
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
