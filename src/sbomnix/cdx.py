#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CycloneDX utils"""

import json
import re

from common import columns as cols
from common.log import LOG, LOG_SPAM
from sbomnix.artifacts import is_non_package_artifact_name
from vulnxscan.utils import _vuln_source, _vuln_url


def _split_meta_homepage(homepage_value):
    """Split flattened homepage metadata into URLs.

    Nix metadata may flatten homepage lists into a single semicolon-separated
    string, but literal homepage URLs can also contain semicolons. Only split
    when the next entry looks like a new URI.
    """
    if not homepage_value:
        return []
    entries = re.split(r";(?=[A-Za-z][A-Za-z0-9+.-]*:)", homepage_value)
    return [entry.strip() for entry in entries if entry.strip()]


def _drv_to_cdx_license_entries(drv):
    """Convert authoritative nixpkgs license entries to CycloneDX licenses."""
    license_entries_json = getattr(drv, "meta_license_entries_json", "")
    if not license_entries_json:
        return []
    try:
        entries = json.loads(license_entries_json)
    except json.JSONDecodeError:
        LOG.debug(
            "Invalid meta_license_entries_json for '%s': %s",
            drv.name,
            license_entries_json,
        )
        return []
    licenses = []
    for entry in entries:
        normalized_entry = entry if isinstance(entry, dict) else {"raw": str(entry)}
        license_id = normalized_entry.get("spdxId")
        license_name = (
            normalized_entry.get("fullName")
            or normalized_entry.get("shortName")
            or normalized_entry.get("raw")
        )
        if license_id:
            licenses.append({"license": {"id": license_id}})
        elif license_name:
            licenses.append({"license": {"name": license_name}})
    return licenses


def _cdx_component_add_licenses(component, drv):
    """Add licenses array to cdx component (if any)"""
    licenses = _drv_to_cdx_license_entries(drv)
    if not licenses:
        LOG.log(LOG_SPAM, "No license info found for '%s'", drv.name)
        return
    # Otherwise, add the licenses entry
    component["licenses"] = licenses


def _cdx_component_add_patches(component, drv):
    """Add security patch information to cdx component (if any)"""
    if drv.patches:
        security_patches = []
        for p in drv.patches.split(" "):
            ids = re.findall(r"CVE-\d{4}-\d+", p, re.IGNORECASE)
            if ids:
                resolves = []
                for i in ids:
                    resolves.append(
                        {
                            "type": "security",
                            "id": i.upper(),
                            "references": [f"file://{p}"],
                        }
                    )
                security_patches.append(
                    {
                        "type": "unofficial",
                        "resolves": resolves,
                    }
                )
        if security_patches:
            pedigree = {}
            pedigree["patches"] = security_patches
            component["pedigree"] = pedigree


def _cdx_component_add_external_references(component, drv):
    """Add CycloneDX external references to a component (if any)."""
    external_references = []
    if "meta_homepage" in drv._asdict() and drv.meta_homepage:
        for homepage_url in _split_meta_homepage(drv.meta_homepage):
            external_references.append({"type": "website", "url": homepage_url})
    if external_references:
        component["externalReferences"] = external_references


def _drv_is_file_component(drv):
    """Return True when a versionless derivation row represents a file artifact."""
    if getattr(drv, "version", ""):
        return False
    candidates = [
        getattr(drv, "name", ""),
        getattr(drv, "pname", ""),
        getattr(drv, "out", ""),
    ]
    outputs = getattr(drv, "outputs", []) or []
    if isinstance(outputs, str):
        candidates.append(outputs)
    else:
        candidates.extend(outputs)
    return any(is_non_package_artifact_name(candidate) for candidate in candidates)


def _drv_to_cdx_component(drv, uid=cols.STORE_PATH):
    """Convert one SBOM component row to a CycloneDX component."""
    component = {}
    component["type"] = "file" if _drv_is_file_component(drv) else "library"
    component["bom-ref"] = getattr(drv, uid)
    component["name"] = drv.pname
    component["version"] = drv.version
    if component["type"] != "file":
        if drv.purl:
            component["purl"] = drv.purl
        if drv.cpe:
            component["cpe"] = drv.cpe
        if "meta_description" in drv._asdict() and drv.meta_description:
            component["description"] = drv.meta_description
        _cdx_component_add_licenses(component, drv)
        _cdx_component_add_patches(component, drv)
        _cdx_component_add_external_references(component, drv)
    properties = []
    for output_path in drv.outputs:
        prop = {}
        prop["name"] = "nix:output_path"
        prop["value"] = output_path
        properties.append(prop)
    if drv.store_path:
        prop = {}
        prop["name"] = "nix:drv_path"
        prop["value"] = drv.store_path
        properties.append(prop)
    # To externalReferences?
    if drv.urls:
        prop = {}
        prop["name"] = "nix:fetch_url"
        prop["value"] = drv.urls
        properties.append(prop)
    if (
        component["type"] != "file"
        and "meta_position" in drv._asdict()
        and drv.meta_position
    ):
        prop = {}
        prop["name"] = "nix:position"
        prop["value"] = drv.meta_position
        properties.append(prop)
    if properties:
        component["properties"] = properties
    return component


def _drv_to_cdx_dependency(drv, deps_list, uid=cols.STORE_PATH):
    """Return CycloneDX dependency structure for one component row."""
    dependency = {}
    dependency["ref"] = getattr(drv, uid)
    if deps_list:
        dependency["dependsOn"] = deps_list
    return dependency


def _vuln_to_cdx_vuln(vuln):
    """Return cdx vulnerability entry from vulnix row"""
    vulnerability = {}
    vulnerability["bom-ref"] = vuln.store_path
    vulnerability["id"] = vuln.vuln_id
    source = {}
    source["url"] = _vuln_url(vuln)
    source["name"] = _vuln_source(vuln)
    vulnerability["source"] = source
    vulnerability["ratings"] = []
    # If the vulnerability is still being assessed, it will be missing a valid number
    if vuln.severity != "":
        rating = {}
        rating["source"] = source
        rating["score"] = vuln.severity
        vulnerability["ratings"].append(rating)
    vulnerability["tools"] = []
    for scanner in vuln.scanner:
        tool = {}
        tool["name"] = scanner
        vulnerability["tools"].append(tool)
    return vulnerability
