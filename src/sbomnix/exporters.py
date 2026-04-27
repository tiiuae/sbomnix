#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""SBOM document exporters and enrichment helpers."""

import json
import pathlib
import re
from datetime import datetime, timezone
from tempfile import NamedTemporaryFile

import pandas as pd
from reuse._licenses import LICENSE_MAP as SPDX_LICENSES

from common.utils import LOG, get_py_pkg_version
from sbomnix.cdx import _drv_to_cdx_component, _drv_to_cdx_dependency, _vuln_to_cdx_vuln
from vulnxscan.vulnscan import VulnScan


def write_json(pathname, data, printinfo=False):
    """Write JSON data to a file."""
    with open(pathname, "w", encoding="utf-8") as outfile:
        json_string = json.dumps(data, indent=2)
        outfile.write(json_string)
        if printinfo:
            LOG.info("Wrote: %s", outfile.name)


def build_cdx_document(sbomdb):
    """Build a CycloneDX document from an SbomDb instance."""
    cdx = {}
    cdx["bomFormat"] = "CycloneDX"
    cdx["specVersion"] = "1.4"
    cdx["version"] = 1
    cdx["serialNumber"] = f"urn:uuid:{sbomdb.uuid}"
    cdx["metadata"] = {}
    cdx["metadata"]["timestamp"] = datetime.now(timezone.utc).astimezone().isoformat()
    cdx["metadata"]["properties"] = []
    prop = {}
    prop["name"] = "sbom_type"
    prop["value"] = sbomdb.sbom_type
    cdx["metadata"]["properties"].append(prop)
    if sbomdb.depth:
        prop = {}
        prop["name"] = "sbom_dependencies_depth"
        prop["value"] = str(sbomdb.depth)
        cdx["metadata"]["properties"].append(prop)
    tool = {}
    tool["vendor"] = "TII"
    tool["name"] = "sbomnix"
    tool["version"] = get_py_pkg_version()
    cdx["metadata"]["tools"] = []
    cdx["metadata"]["tools"].append(tool)
    cdx["components"] = []
    cdx["dependencies"] = []
    for drv in sbomdb.df_sbomdb.itertuples():
        component = _drv_to_cdx_component(drv, uid=sbomdb.uid)
        if drv.store_path == sbomdb.target_deriver:
            cdx["metadata"]["component"] = component
        else:
            cdx["components"].append(component)
        deps = sbomdb.lookup_dependencies(drv, uid=sbomdb.uid)
        dependency = _drv_to_cdx_dependency(drv, deps, uid=sbomdb.uid)
        cdx["dependencies"].append(dependency)
    return cdx


def enrich_cdx_with_vulnerabilities(sbomdb, cdx):
    """Add vulnerability scan results to an existing CycloneDX document."""
    scanner = VulnScan()
    scanner.scan_vulnix(sbomdb.target_deriver, sbomdb.buildtime)
    temp_cdx_path = None
    try:
        with NamedTemporaryFile(
            delete=False, prefix="vulnxscan_", suffix=".json"
        ) as fcdx:
            temp_cdx_path = fcdx.name
            write_json(temp_cdx_path, cdx, printinfo=False)
        scanner.scan_grype(temp_cdx_path)
        scanner.scan_osv(temp_cdx_path)
    finally:
        if temp_cdx_path is not None:
            pathlib.Path(temp_cdx_path).unlink(missing_ok=True)

    cdx["vulnerabilities"] = []
    df_vulns = pd.concat(
        [scanner.df_grype, scanner.df_osv, scanner.df_vulnix],
        ignore_index=True,
    )
    if df_vulns.empty:
        return cdx
    if "modified" in df_vulns.columns:
        df_vulns = df_vulns.drop("modified", axis=1)
    vuln_grouped = df_vulns.groupby(
        ["package", "version", "severity", "vuln_id"],
        as_index=False,
    ).agg({"scanner": pd.Series.unique})
    vuln_components = pd.merge(
        left=vuln_grouped,
        right=sbomdb.df_sbomdb,
        how="inner",
        left_on=["package", "version"],
        right_on=["pname", "version"],
    )
    for vuln in vuln_components.itertuples():
        cdx_vuln = _vuln_to_cdx_vuln(vuln)
        cdx["vulnerabilities"].append(cdx_vuln)
    return cdx


def _str_to_spdxid(strval):
    # Only letters, numbers, '.', and '-' are allowed in spdx idstring,
    # replace all other characters with '-'
    idstring = re.sub(r"[^\-.a-zA-Z0-9]", "-", strval)
    # Return idstring with prefix "SPDXRef-"
    if idstring.startswith("-"):
        return f"SPDXRef{idstring}"
    return f"SPDXRef-{idstring}"


def _drv_to_spdx_license_list(drv):
    license_attr_name = "meta_license_spdxid"
    if license_attr_name not in drv._asdict():
        return []
    license_str = getattr(drv, license_attr_name)
    if not license_str:
        return []
    license_strings = license_str.split(";")
    licenses = []
    for license_string in license_strings:
        if license_string not in SPDX_LICENSES:
            continue
        licenses.append(license_string)
    return licenses


def _drv_to_spdx_extrefs(drv):
    extrefs = []
    if drv.cpe:
        cpe_ref = {}
        cpe_ref["referenceCategory"] = "SECURITY"
        cpe_ref["referenceType"] = "cpe23Type"
        cpe_ref["referenceLocator"] = drv.cpe
        extrefs.append(cpe_ref)
    if drv.purl:
        purl_ref = {}
        purl_ref["referenceCategory"] = "PACKAGE-MANAGER"
        purl_ref["referenceType"] = "purl"
        purl_ref["referenceLocator"] = drv.purl
        extrefs.append(purl_ref)
    return extrefs


def _drv_to_spdx_package(drv, uid="store_path"):
    """Convert one entry from sbomdb (drv) to an SPDX package."""
    pkg = {}
    pkg["name"] = drv.pname
    pkg["SPDXID"] = _str_to_spdxid(getattr(drv, uid))
    pkg["versionInfo"] = drv.version
    pkg["downloadLocation"] = "NOASSERTION"
    if drv.urls:
        pkg["downloadLocation"] = drv.urls
    if "meta_homepage" in drv._asdict() and drv.meta_homepage:
        pkg["homepage"] = drv.meta_homepage
    if "meta_description" in drv._asdict() and drv.meta_description:
        pkg["summary"] = drv.meta_description
    licenses = _drv_to_spdx_license_list(drv)
    if licenses:
        pkg["licenseInfoFromFiles"] = licenses
    licence_entry = licenses[0] if len(licenses) == 1 else "NOASSERTION"
    pkg["licenseConcluded"] = licence_entry
    pkg["licenseDeclared"] = licence_entry
    pkg["copyrightText"] = "NOASSERTION"
    extrefs = _drv_to_spdx_extrefs(drv)
    if extrefs:
        pkg["externalRefs"] = extrefs
    return pkg


def _drv_to_spdx_relationships(drv, deps_list, uid="store_path"):
    """Return list of SPDX relationships for one sbomdb row."""
    relationships = []
    if not deps_list:
        return relationships
    drv_spdxid = _str_to_spdxid(getattr(drv, uid))
    relationship_type = "DEPENDS_ON"
    for dep in deps_list:
        relationship = {}
        relationship["spdxElementId"] = drv_spdxid
        relationship["relationshipType"] = relationship_type
        relationship["relatedSpdxElement"] = _str_to_spdxid(dep)
        relationships.append(relationship)
    return relationships


def build_spdx_document(sbomdb):
    """Build an SPDX document from an SbomDb instance."""
    spdx = {}
    spdx["spdxVersion"] = "SPDX-2.3"
    spdx["dataLicense"] = "CC0-1.0"
    spdx["SPDXID"] = "SPDXRef-DOCUMENT"
    spdx["name"] = ""
    spdx["documentNamespace"] = f"sbomnix://{sbomdb.uuid}"
    creation_info = {}
    creation_info["created"] = datetime.now(timezone.utc).astimezone().isoformat()
    creation_info["creators"] = []
    creation_info["creators"].append(f"Tool: sbomnix-{get_py_pkg_version()}")
    spdx["creationInfo"] = creation_info
    spdx["comment"] = f"included dependencies: '{sbomdb.sbom_type}'"
    spdx["packages"] = []
    spdx["relationships"] = []
    for drv in sbomdb.df_sbomdb.itertuples():
        package = _drv_to_spdx_package(drv, uid=sbomdb.uid)
        spdx["packages"].append(package)
        if drv.store_path == sbomdb.target_deriver:
            spdx["name"] = _str_to_spdxid(getattr(drv, sbomdb.uid))
        deps = sbomdb.lookup_dependencies(drv, uid=sbomdb.uid)
        relationships = _drv_to_spdx_relationships(drv, deps, uid=sbomdb.uid)
        for relation in relationships:
            spdx["relationships"].append(relation)
    return spdx
