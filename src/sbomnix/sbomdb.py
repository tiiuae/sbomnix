#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-instance-attributes, too-many-arguments
# pylint: disable=too-many-positional-arguments

"""Module for generating SBOMs in various formats"""

import argparse
import logging
import uuid

import numpy as np

from common.df import df_to_csv_file
from common.log import LOG
from nixgraph.graph import NixDependencies
from sbomnix.dependency_index import build_dependency_index
from sbomnix.exporters import build_cdx_document, build_spdx_document, write_json
from sbomnix.meta import Meta
from sbomnix.nix import Store, find_deriver
from sbomnix.vuln_enrichment import enrich_cdx_with_vulnerabilities

###############################################################################

# Namespace UUID (a UUIDv4) for stable UUIDv5 identifiers.
# See RFC9562, *6.6.  Namespace ID Usage and Allocation*.
SBOMNIX_UUID_NAMESPACE = uuid.UUID("136af32e-0d0e-48bc-912c-31b26af294b9")

###############################################################################


class SbomDb:
    """Generates SBOMs in various formats"""

    def __init__(
        self,
        nix_path,
        buildtime=False,
        depth=None,
        flakeref=None,
        include_meta=True,
        include_vulns=False,
        include_cpe=True,
    ):
        # self.uid specifies the attribute that SbomDb uses as unique
        # identifier for the sbom components. See the column names in
        # self.df_sbomdb (sbom.csv) for a list of all components' attributes.
        self.uid = "store_path"
        self.nix_path = nix_path
        self.buildtime = buildtime
        self.target_deriver = find_deriver(nix_path)
        self.df_deps = None
        self.depth = depth
        self._init_dependencies(nix_path)
        self.df_sbomdb = None
        self.df_sbomdb_outputs_exploded = None
        self.dependency_index = None
        self.flakeref = flakeref
        self.meta = None
        self.include_cpe = include_cpe
        self._init_sbomdb(include_meta)
        self.include_vulns = include_vulns
        # Use a random UUID as the serial number when any data source that is
        # not strictly coming from the target_deriver is used
        if include_vulns or include_meta or include_cpe:
            LOG.info("Using random UUIDv4")
            self.uuid = uuid.uuid4()
        else:
            LOG.info("Using stable UUIDv5 for '%s'", self.target_deriver)
            # This uses a UUIDv5, which uses the deriver's store path as its input,
            # resulting in a stable UUID across runs, depending on the SBOM's subject.
            self.uuid = uuid.uuid5(SBOMNIX_UUID_NAMESPACE, self.target_deriver)
        self.sbom_type = "runtime_and_buildtime"
        if not self.buildtime:
            self.sbom_type = "runtime_only"

    def _init_dependencies(self, nix_path):
        """Initialize dependencies (df_deps)"""
        if self.buildtime:
            buildtime_dependencies = NixDependencies(nix_path, buildtime=True)
            self.df_deps = self._get_dependencies_df(buildtime_dependencies)
        else:
            runtime_dependencies = NixDependencies(nix_path, buildtime=False)
            self.df_deps = self._get_dependencies_df(runtime_dependencies)

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
        if self.df_deps is None or self.df_deps.empty:
            # No dependencies, so the only component in the sbom
            # will be the target itself
            paths = set([self.target_deriver])
        else:
            # Get unique src_paths and target_paths
            src_paths = self.df_deps["src_path"].unique().tolist()
            target_paths = self.df_deps["target_path"].unique().tolist()
            paths = set(src_paths + target_paths)
        # Populate store based on the dependencies
        store = Store(self.buildtime, include_cpe=self.include_cpe)
        store.add_paths(paths)
        self.df_sbomdb = store.to_dataframe()
        # Join with meta information
        if include_meta:
            self._sbomdb_join_meta()
        # Clean, drop duplicates, sort
        self.df_sbomdb.replace(np.nan, "", regex=True, inplace=True)
        self.df_sbomdb.drop_duplicates(subset=[self.uid], keep="first", inplace=True)
        self.df_sbomdb.sort_values(by=["name", self.uid], inplace=True)
        self.df_sbomdb_outputs_exploded = self.df_sbomdb.explode("outputs")
        self._init_dependency_index()

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
        self.meta = Meta()
        if self.flakeref:
            df_meta = self.meta.get_nixpkgs_meta(self.flakeref)
        else:
            df_meta = self.meta.get_nixpkgs_meta()
        if df_meta is None or df_meta.empty:
            LOG.warning(
                "Failed reading nix meta information: "
                "SBOM will include only minimum set of attributes"
            )
            return
        if LOG.level <= logging.DEBUG:
            df_to_csv_file(df_meta, "meta.csv")
        # Join based on package name including the version number
        self.df_sbomdb = self.df_sbomdb.merge(
            df_meta,
            how="left",
            left_on=["name"],
            right_on=["name"],
            suffixes=["", "_meta"],
        )

    def lookup_dependencies(self, drv, uid="store_path"):
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

    def _lookup_dependencies(self, drv, uid="store_path"):
        """Backward-compatible alias for lookup_dependencies."""
        return self.lookup_dependencies(drv, uid=uid)

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
