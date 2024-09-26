#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

""" CycloneDX utils """

import re

from reuse._licenses import LICENSE_MAP as SPDX_LICENSES
from common.utils import LOG, LOG_SPAM
from vulnxscan.utils import _vuln_source, _vuln_url


def _drv_to_cdx_licenses_entry(drv, column_name, cdx_license_type):
    """Parse license entries of type cdx_license_type from column_name"""
    licenses = []
    if column_name not in drv._asdict():
        # Return empty list if column name is not in drv
        return licenses
    license_str = getattr(drv, column_name)
    if not license_str:
        # Return empty list if license string is empty
        return licenses
    # Parse the ";" separated licenses to cdx license format
    license_strings = license_str.split(";")
    for license_string in license_strings:
        # Give up generating the 'licenses' entry if license id should be
        # spdx but it's not:
        if "spdxid" in column_name and license_string not in SPDX_LICENSES:
            LOG.debug("Invalid spdxid license '%s':'%s'", drv.name, license_string)
            return []
        license_dict = {"license": {cdx_license_type: license_string}}
        licenses.append(license_dict)
    return licenses


def _cdx_component_add_licenses(component, drv):
    """Add licenses array to cdx component (if any)"""
    licenses = []
    # First, try reading the license in spdxid-format
    licenses = _drv_to_cdx_licenses_entry(drv, "meta_license_spdxid", "id")
    # If it fails, try reading the license short name
    if not licenses:
        licenses = _drv_to_cdx_licenses_entry(drv, "meta_license_short", "name")
    # Give up if package does not have license information associated
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


def _drv_to_cdx_component(drv, uid="store_path"):
    """Convert one entry from sbomdb (drv) to cdx component"""
    component = {}
    component["type"] = "application"
    component["bom-ref"] = getattr(drv, uid)
    component["name"] = drv.pname
    component["version"] = drv.version
    if drv.purl:
        component["purl"] = drv.purl
    if drv.cpe:
        component["cpe"] = drv.cpe
    if "meta_description" in drv._asdict() and drv.meta_description:
        component["description"] = drv.meta_description
    _cdx_component_add_licenses(component, drv)
    _cdx_component_add_patches(component, drv)
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
    if "meta_homepage" in drv._asdict() and drv.meta_homepage:
        prop = {}
        prop["name"] = "homepage"
        prop["value"] = drv.meta_homepage
        properties.append(prop)
    if properties:
        component["properties"] = properties
    return component


def _drv_to_cdx_dependency(drv, deps_list, uid="store_path"):
    """Return cdx dependency structure for sbomdb drv"""
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
