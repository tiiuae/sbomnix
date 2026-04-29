#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""SBOM document exporters."""

import json
import re
from datetime import datetime, timezone

from common import columns as cols
from common.log import LOG
from common.pkgmeta import get_py_pkg_version
from common.spdx import canonicalize_spdx_license_id
from sbomnix.cdx import _drv_to_cdx_component, _drv_to_cdx_dependency

_NIXPKGS_META_SOURCE_FIELDS = (
    ("nixpkgs:metadata_source_method", "method"),
    ("nixpkgs:path", "path"),
    ("nixpkgs:rev", "rev"),
    ("nixpkgs:flakeref", "flakeref"),
    ("nixpkgs:version", "version"),
    ("nixpkgs:message", "message"),
)


def write_json(pathname, data, printinfo=False):
    """Write JSON data to a file."""
    with open(pathname, "w", encoding="utf-8") as outfile:
        json_string = json.dumps(data, indent=2)
        outfile.write(json_string)
        if printinfo:
            LOG.info("Wrote: %s", outfile.name)


def _nixpkgs_meta_source_properties(sbomdb):
    """Return non-empty document properties for nixpkgs metadata source."""
    source = getattr(sbomdb, "nixpkgs_meta_source", None)
    if source is None:
        return []
    properties = []
    for property_name, attr_name in _NIXPKGS_META_SOURCE_FIELDS:
        value = getattr(source, attr_name)
        if value:
            properties.append({"name": property_name, "value": str(value)})
    return properties


def _spdx_nixpkgs_meta_source_comment(sbomdb):
    """Return a compact SPDX comment line for nixpkgs metadata source."""
    source = getattr(sbomdb, "nixpkgs_meta_source", None)
    if source is None:
        return None
    fields = []
    for property_name, attr_name in _NIXPKGS_META_SOURCE_FIELDS:
        value = getattr(source, attr_name)
        if value:
            fields.append(f"{property_name.removeprefix('nixpkgs:')}={value}")
    if not fields:
        return None
    return "nixpkgs metadata source: " + "; ".join(fields)


def build_cdx_document(sbomdb):
    """Build a CycloneDX document from an SBOM builder."""
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
    cdx["metadata"]["properties"].extend(_nixpkgs_meta_source_properties(sbomdb))
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
        if drv.store_path == sbomdb.target_component_ref:
            cdx["metadata"]["component"] = component
        else:
            cdx["components"].append(component)
        deps = sbomdb.lookup_dependencies(drv, uid=sbomdb.uid)
        dependency = _drv_to_cdx_dependency(drv, deps, uid=sbomdb.uid)
        cdx["dependencies"].append(dependency)
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
        canonical = canonicalize_spdx_license_id(license_string)
        if not canonical:
            continue
        licenses.append(canonical)
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


def _drv_to_spdx_package(drv, uid=cols.STORE_PATH):
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


def _drv_to_spdx_relationships(drv, deps_list, uid=cols.STORE_PATH):
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
    """Build an SPDX document from an SBOM builder."""
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
    comments = [f"included dependencies: '{sbomdb.sbom_type}'"]
    source_comment = _spdx_nixpkgs_meta_source_comment(sbomdb)
    if source_comment:
        comments.append(source_comment)
    spdx["comment"] = "\n".join(comments)
    spdx["packages"] = []
    spdx["relationships"] = []
    for drv in sbomdb.df_sbomdb.itertuples():
        package = _drv_to_spdx_package(drv, uid=sbomdb.uid)
        spdx["packages"].append(package)
        if drv.store_path == sbomdb.target_component_ref:
            spdx["name"] = _str_to_spdxid(getattr(drv, sbomdb.uid))
        deps = sbomdb.lookup_dependencies(drv, uid=sbomdb.uid)
        relationships = _drv_to_spdx_relationships(drv, deps, uid=sbomdb.uid)
        for relation in relationships:
            spdx["relationships"].append(relation)
    return spdx
