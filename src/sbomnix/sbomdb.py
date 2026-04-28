#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Module for generating SBOMs in various formats"""

import argparse
import logging
import subprocess
import uuid

import numpy as np
import pandas as pd

from common import columns as cols
from common.df import df_to_csv_file
from common.log import LOG, is_debug_enabled
from nixgraph.graph import NixDependencies
from nixgraph.render import NixDependencyGraph
from sbomnix.dependency_index import build_dependency_index
from sbomnix.derivation import load_recursive
from sbomnix.exporters import build_cdx_document, build_spdx_document, write_json
from sbomnix.meta import Meta, NixpkgsMetaSource
from sbomnix.nix import Store, find_deriver
from sbomnix.vuln_enrichment import enrich_cdx_with_vulnerabilities

###############################################################################

# Namespace UUID (a UUIDv4) for stable UUIDv5 identifiers.
# See RFC9562, *6.6.  Namespace ID Usage and Allocation*.
SBOMNIX_UUID_NAMESPACE = uuid.UUID("136af32e-0d0e-48bc-912c-31b26af294b9")

###############################################################################

_DEPENDENCY_COLUMNS = [
    cols.SRC_PATH,
    "src_pname",
    cols.TARGET_PATH,
    "target_pname",
]


def _recursive_buildtime_dependencies_df(drv_infos):
    """Return build-time dependency edges from recursive derivation JSON."""
    rows = []
    for target_path, drv_info in drv_infos.items():
        for src_path in _iter_input_drv_paths(drv_info):
            rows.append(
                {
                    cols.SRC_PATH: src_path,
                    "src_pname": _store_path_label(src_path),
                    cols.TARGET_PATH: target_path,
                    "target_pname": _store_path_label(target_path),
                }
            )
    df = pd.DataFrame.from_records(rows, columns=_DEPENDENCY_COLUMNS)
    if not df.empty:
        df.drop_duplicates(inplace=True)
        df.sort_values(
            by=["src_pname", cols.SRC_PATH, "target_pname", cols.TARGET_PATH],
            inplace=True,
        )
    return df


def _iter_input_drv_paths(drv_info):
    """Yield input derivation paths from old and new derivation JSON formats."""
    inputs = drv_info.get("inputs", {})
    if isinstance(inputs, dict):
        drvs = inputs.get("drvs", {})
        if isinstance(drvs, dict):
            yield from drvs
    input_drvs = drv_info.get("inputDrvs", {})
    if isinstance(input_drvs, dict):
        yield from input_drvs


def _store_path_label(path):
    """Return the nix-store graph-style label for a store path."""
    basename = str(path).rstrip("/").rsplit("/", maxsplit=1)[-1]
    _hash, separator, name = basename.partition("-")
    return name if separator else basename


class SbomDb:
    """Generates SBOMs in various formats"""

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
        # self.uid specifies the attribute that SbomDb uses as unique
        # identifier for the sbom components. See the column names in
        # self.df_sbomdb (sbom.csv) for a list of all components' attributes.
        self.uid = cols.STORE_PATH
        self.nix_path = nix_path
        self.buildtime = buildtime
        self.target_deriver = find_deriver(nix_path)
        if self.target_deriver is None:
            raise RuntimeError(f"Failed finding deriver for '{nix_path}'")
        self._recursive_buildtime_derivations = None
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
        self._init_sbomdb(include_meta)
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
        if self.buildtime and self._init_recursive_buildtime_dependencies():
            return
        nix_dependencies = NixDependencies(
            nix_path,
            buildtime=self.buildtime,
            drv_path=self.target_deriver,
            resolve_output=self.depth is not None,
        )
        self.df_deps = self._get_dependencies_df(nix_dependencies)

    def _init_recursive_buildtime_dependencies(self):
        """Initialize build-time dependencies from recursive derivation JSON."""
        try:
            derivations, drv_infos = load_recursive(self.target_deriver)
        except (RuntimeError, subprocess.CalledProcessError, ValueError):
            LOG.debug("Failed loading recursive derivation closure", exc_info=True)
            LOG.warning(
                "Falling back to nix-store buildtime graph for '%s'",
                self.target_deriver,
            )
            return False
        self._recursive_buildtime_derivations = derivations
        self.df_deps = _recursive_buildtime_dependencies_df(drv_infos)
        if self.depth:
            self.df_deps = self._filter_dependencies_to_depth(
                self.df_deps,
                self.target_deriver,
                self.depth,
            )
        return True

    def _filter_dependencies_to_depth(self, df_deps, start_path, depth):
        """Return dependency rows reachable from ``start_path`` up to ``depth``."""
        LOG.debug("Reading dependencies until depth=%s", depth)
        args = argparse.Namespace()
        args.depth = depth
        args.return_df = True
        df_depth = NixDependencyGraph(df_deps).draw(start_path, args)
        if df_depth is None:
            return pd.DataFrame(columns=pd.Index(_DEPENDENCY_COLUMNS))
        return df_depth.drop(columns=["graph_depth"], errors="ignore")

    def _get_dependencies_df(self, nix_dependencies):
        if self.depth:
            # Return dependencies until the given depth
            LOG.debug("Reading dependencies until depth=%s", self.depth)
            args = argparse.Namespace()
            args.depth = self.depth
            args.return_df = True
            return nix_dependencies.graph(args)
        # Otherwise, return all dependencies
        LOG.debug("Reading all dependencies")
        return nix_dependencies.to_dataframe()

    def _init_sbomdb(self, include_meta):
        """Initialize self.df_sbomdb"""
        paths = self._sbom_component_paths()
        # Populate store based on the dependencies
        if self._recursive_buildtime_derivations is None:
            store = Store(self.buildtime, include_cpe=self.include_cpe)
            store.add_paths(paths)
            self.df_sbomdb = store.to_dataframe()
        else:
            self.df_sbomdb = self._recursive_derivations_to_dataframe(paths)
        # Join with meta information
        if include_meta:
            self._sbomdb_join_meta()
        # Clean, drop duplicates, sort
        self.df_sbomdb.replace(np.nan, "", regex=True, inplace=True)
        self.df_sbomdb.drop_duplicates(subset=[self.uid], keep="first", inplace=True)
        self.df_sbomdb.sort_values(by=[cols.NAME, self.uid], inplace=True)
        self.df_sbomdb_outputs_exploded = self.df_sbomdb.explode(cols.OUTPUTS)
        self._init_dependency_index()

    def _sbom_component_paths(self):
        if self.df_deps is None or self.df_deps.empty:
            # No dependencies, so the only component in the sbom
            # will be the target itself.
            return set([self.target_deriver])
        # Get unique src_paths and target_paths.
        src_paths = self.df_deps[cols.SRC_PATH].unique().tolist()
        target_paths = self.df_deps[cols.TARGET_PATH].unique().tolist()
        return set(src_paths + target_paths)

    def _recursive_derivations_to_dataframe(self, paths):
        drv_dicts = []
        derivations = self._recursive_buildtime_derivations
        assert derivations is not None
        cpe_generator = Store(
            self.buildtime, include_cpe=self.include_cpe
        ).cpe_generator
        for path in sorted(paths):
            drv = derivations.get(path)
            if not drv:
                LOG.debug("Recursive buildtime closure missing path: %s", path)
                continue
            drv.set_cpe(cpe_generator)
            drv_dicts.append(drv.to_dict())
        return pd.DataFrame.from_records(drv_dicts)

    def _init_dependency_index(self):
        """Build indexed dependency lookups used during export."""
        self.dependency_index = build_dependency_index(
            self.df_deps,
            self.df_sbomdb,
            self.df_sbomdb_outputs_exploded,
            uid=self.uid,
        )

    def _sbomdb_join_meta(self):
        """Join self.df_sbomdb with meta information"""
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
        """
        Lookup the runtime and buildtime dependencies for `drv`.
        Returns a list of unique dependencies as specified by the
        dependencies' attribute (column) `uid` values.
        By default, returns the list of unique `store_path` values
        which includes the build and runtime dependencies of `drv`.
        """
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
        """Export sbomdb to cyclonedx json file"""
        cdx = self.to_cdx_data()
        self.write_json(cdx_path, cdx, printinfo)

    def to_spdx(self, spdx_path, printinfo=True):
        """Export sbomdb to spdx json file"""
        spdx = self.to_spdx_data()
        self.write_json(spdx_path, spdx, printinfo)

    def to_csv(self, csv_path, loglevel=logging.INFO):
        """Export sbomdb to csv file"""
        df_to_csv_file(self.df_sbomdb, csv_path, loglevel)
