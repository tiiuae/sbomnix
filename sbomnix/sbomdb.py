#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=fixme,invalid-name

""" Module for generating SBOMs in various formats """

import uuid
import logging
import json
import re
import pandas as pd
import numpy as np
from reuse._licenses import LICENSE_MAP as SPDX_LICENSES
from packageurl import PackageURL
from nixgraph.graph import NixDependencies
from sbomnix.nix import Store
from sbomnix.utils import (
    LOGGER_NAME,
    df_to_csv_file,
)

###############################################################################

_LOG = logging.getLogger(LOGGER_NAME)

###############################################################################


class SbomDb:
    """Generates SBOMs in various formats"""

    def __init__(self, nix_path, runtime=False, meta_path=None):
        self.store = Store(nix_path, runtime)
        self.df_sbomdb = self._get_sbomdb(meta_path)
        # Read runtime and buildtime dependencies
        df_rdeps = self._get_runtime_deps(nix_path)
        df_bdeps = None
        # No need to parse buildtime dependencies if 'runtime' was requested:
        if not runtime:
            df_bdeps = self._get_buildtime_deps(nix_path)
        # Concat buildtime and runtime dependencies dropping duplicates
        self.df_deps = pd.concat([df_rdeps, df_bdeps], ignore_index=True)
        self.df_deps.drop_duplicates()
        # Remove dependencies to packages that don't exist in sbom. Such
        # packages might exist in df_deps because packages in sbom are
        # cleaned as per IGNORE_NAMES in derivation.py
        sbom = list(self.df_sbomdb["purl"].unique())
        self.df_deps = self.df_deps[self.df_deps["depends_on_purl"].isin(sbom)]
        # To see which dependencies are dropped, try:
        # self.df_deps = self.df_deps[~self.df_deps["depends_on_purl"].isin(sbom)]
        # then run with '--verbose=2' and then check the following file:
        if _LOG.level <= logging.DEBUG:
            df_to_csv_file(self.df_deps, "sbomdb_deps.csv")

    def _get_runtime_deps(self, nix_path):
        """Return 'nix_path' runtime dependencies as dataframe"""
        runtime_deps = NixDependencies(nix_path, buildtime=False)
        df = runtime_deps.to_dataframe()
        if df is None:
            _LOG.warning("Failed finding runtime dependencies for '%s'", nix_path)
            return None
        # Join runtime dependency data with sbomdb
        df_deps = self.df_sbomdb.merge(
            df,
            how="left",
            left_on=["out"],
            right_on=["target_path"],
            suffixes=["", "_right"],
        )
        return self._src_path_to_purl(df_deps, runtime=True)

    def _get_buildtime_deps(self, nix_path):
        """Return 'nix_path' buildtime dependencies as dataframe"""
        buildtime_deps = NixDependencies(nix_path, buildtime=True)
        df = buildtime_deps.to_dataframe()
        if df is None:
            _LOG.warning("Failed finding buildtime dependencies for '%s'", nix_path)
            return None
        # Join buildtime dependency data with sbomdb
        df_deps = self.df_sbomdb.merge(
            df,
            how="left",
            left_on=["store_path"],
            right_on=["target_path"],
            suffixes=["", "_right"],
        )
        return self._src_path_to_purl(df_deps, runtime=False)

    def _src_path_to_purl(self, df_deps, runtime):
        """Generate df_deps.purl based on df_deps.src_path"""
        if runtime:
            deps_debug_out = "sbomdb_runtime_deps.csv"
            re_split = re.compile(
                r"""/nix/store/[^-]+-(.+?)-([0-9].+)|  # with version number
                    /nix/store/[^-]+-(.+?)""",  # without version number
                re.X,
            )
        else:
            deps_debug_out = "sbomdb_buildtime_deps.csv"
            re_split = re.compile(
                r"""/nix/store/[^-]+-(.+?)-([0-9].+)\.drv|  # with version number
                    /nix/store/[^-]+-(.+?)\.drv""",  # without version number
                re.X,
            )
        # Add df_deps.purl based on df_deps.src_path
        selected_columns = ["purl", "src_path"]
        df_deps = df_deps[selected_columns]
        df_deps = df_deps[df_deps.src_path.notnull()]
        # Split src_path to name and version
        re_cols = ["name", "ver", "name_no_ver"]
        df_deps[re_cols] = df_deps["src_path"].str.extract(re_split, expand=True)
        # Drop rows where all re_cols column values are nan
        df_deps = df_deps.dropna(axis=0, how="all", subset=re_cols)
        # Construct purl for the depends-on packages, use package name and
        # version when available, otherwise, use only the name
        df_deps["depends_on_purl"] = df_deps.apply(
            lambda x: purl(x["name"], x["ver"])
            if not pd.isnull(x["ver"])
            else purl(x["name_no_ver"]),
            axis=1,
        )
        # Only keep the selected_columns
        selected_columns = ["purl", "depends_on_purl"]
        df_deps = df_deps[selected_columns]
        if _LOG.level <= logging.DEBUG:
            df_to_csv_file(df_deps, deps_debug_out)
        return df_deps

    def _get_sbomdb(self, meta_path):
        """Convert SbomDb to dataframe (joined with meta information)"""
        df_store = self.store.to_dataframe()
        df_sbomdb = df_store
        if meta_path is not None:
            df_meta = _parse_json_metadata(meta_path)
            if _LOG.level <= logging.DEBUG:
                df_to_csv_file(df_meta, "meta.csv")
            # Join based on package name including the version number
            df_sbomdb = df_store.merge(
                df_meta,
                how="left",
                left_on=["name"],
                right_on=["name"],
                suffixes=["", "_meta"],
            )
        df_sbom = df_sbomdb.replace(np.nan, "", regex=True)
        return df_sbom.drop_duplicates(subset=["purl"], keep="first")

    def to_cdx(self, cdx_path):
        """Export sbomdb to cyclonedx json file"""
        target_path = self.store.get_target_drv_path()
        cdx = {}
        cdx["bomFormat"] = "CycloneDX"
        cdx["specVersion"] = "1.3"
        cdx["version"] = 1
        cdx["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
        cdx["metadata"] = {}
        tool = {}
        tool["vendor"] = "TII"
        tool["name"] = "sbomnix"
        tool["version"] = "0.1.0"
        cdx["metadata"]["tools"] = []
        cdx["metadata"]["tools"].append(tool)
        cdx["components"] = []
        cdx["dependencies"] = []
        for row in self.df_sbomdb.itertuples():
            component = _df_row_to_cdx_component(row)
            if row.store_path == target_path:
                cdx["metadata"]["component"] = component
            else:
                cdx["components"].append(component)
            dependency = _df_row_to_dependency(row, self.df_deps)
            cdx["dependencies"].append(dependency)

        with open(cdx_path, "w", encoding="utf-8") as outfile:
            json_string = json.dumps(cdx, indent=2)
            outfile.write(json_string)
            _LOG.info("Wrote: %s", outfile.name)

    def to_csv(self, csv_path):
        """Export sbomdb to csv file"""
        df_to_csv_file(self.df_sbomdb, csv_path)


def purl(purl_name, purl_version=""):
    """Return PackageURL string given the name and version"""
    return str(PackageURL(type="nix", name=purl_name, version=purl_version))


################################################################################

# CycloneDX


def _licenses_entry_from_row(row, column_name, cdx_license_type):
    """Parse license entries of type cdx_license_type from column_name"""
    licenses = []
    if column_name not in row._asdict():
        # Return empty list if column name is not in row
        return licenses
    license_str = getattr(row, column_name)
    if not license_str:
        # Return empty list if license string is empty
        return licenses
    # Parse the ";" separated licenses to cdx license format
    license_strings = license_str.split(";")
    for license_string in license_strings:
        # Give up generating the 'licenses' entry if license id should be
        # spdx but it's not:
        if "spdxid" in column_name and license_string not in SPDX_LICENSES:
            _LOG.debug("Invalid spdxid license '%s':'%s'", row.name, license_string)
            return []
        license_dict = {"license": {cdx_license_type: license_string}}
        licenses.append(license_dict)
    return licenses


def _cdx_component_add_licenses(component, row):
    """Add licenses array to cdx component (if any)"""
    licenses = []
    # First, try reading the license in spdxid-format
    licenses = _licenses_entry_from_row(row, "meta_license_spdxid", "id")
    # If it fails, try reading the license short name
    if not licenses:
        licenses = _licenses_entry_from_row(row, "meta_license_short", "name")
    # Give up if pacakge does not have license information associated
    if not licenses:
        _LOG.debug("No license info found for '%s'", row.name)
        return
    # Otherwise, add the licenses entry
    component["licenses"] = licenses


def _df_row_to_cdx_component(row):
    """Convert one entry from sbomdb (row) to cdx component"""
    component = {}
    component["type"] = "application"
    component["bom-ref"] = row.purl
    component["name"] = row.pname
    component["version"] = row.version
    component["purl"] = row.purl
    component["cpe"] = row.cpe
    _cdx_component_add_licenses(component, row)
    return component


def _df_row_to_dependency(row, df_deps):
    """Return cdx dependency structure for sbomdb row"""
    dependency = {}
    dependency["ref"] = row.purl
    df_deps_ons = df_deps[df_deps["purl"] == row.purl]
    deps_on_purls = list(df_deps_ons["depends_on_purl"].unique())
    if deps_on_purls:
        dependency["dependsOn"] = deps_on_purls
    return dependency


###############################################################################

# Nix package metadata


def _parse_meta_entry(meta, key):
    """Parse the given key from the metadata entry"""
    if isinstance(meta, dict):
        ret = [meta.get(key, "")]
    elif isinstance(meta, list):
        ret = [x.get(key, "") if isinstance(x, dict) else x for x in meta]
    else:
        ret = [meta]
    return list(filter(None, ret))


def _parse_json_metadata(json_filename):
    """Parse package metadata from the specified json file"""

    with open(json_filename, "r", encoding="utf-8") as inf:
        _LOG.info('Loading meta info from "%s"', json_filename)
        json_dict = json.loads(inf.read())

        dict_selected = {}
        setcol = dict_selected.setdefault
        for nixpkg_name, pkg in json_dict.items():
            # generic package info
            setcol("nixpkgs", []).append(nixpkg_name)
            setcol("name", []).append(pkg.get("name", ""))
            setcol("pname", []).append(pkg.get("pname", ""))
            setcol("version", []).append(pkg.get("version", ""))
            # meta
            meta = pkg.get("meta", {})
            setcol("meta_homepage", []).append(meta.get("homepage", ""))
            setcol("meta_position", []).append(meta.get("position", ""))
            # meta.license
            meta_license = meta.get("license", {})
            license_short = _parse_meta_entry(meta_license, key="shortName")
            setcol("meta_license_short", []).append(";".join(license_short))
            license_spdx = _parse_meta_entry(meta_license, key="spdxId")
            setcol("meta_license_spdxid", []).append(";".join(license_spdx))
            # meta.maintainers
            meta_maintainers = meta.get("maintainers", {})
            emails = _parse_meta_entry(meta_maintainers, key="email")
            setcol("meta_maintainers_email", []).append(";".join(emails))

        return pd.DataFrame(dict_selected)


################################################################################
