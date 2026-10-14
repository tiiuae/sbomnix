#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Andrzej Piotrowski
#
# SPDX-License-Identifier: Apache-2.0

"""Convert sbomnix CycloneDX output into SBOM Explorer compatible JSON."""

import json
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from common.log import LOG


###############################################################################


def _component_count(cdx):
    """Count components in CycloneDX document."""
    return len(cdx.get("components", []))


def _extract_licenses(component):
    """Extract license names from a CycloneDX component."""
    licenses = []
    for lic in component.get("licenses", []):
        lic_data = lic.get("license", {})
        name = lic_data.get("name") or lic_data.get("id", "unknown")
        if name:
            licenses.append(name)
    return licenses


def _nix_meta_from_cdx(cdx):
    """Extract Nix-specific metadata from sbomnix CycloneDX properties."""
    meta = {}
    props = cdx.get("metadata", {}).get("properties", [])
    for prop in props:
        if prop.get("name") == "sbom_type":
            meta["sbom_type"] = prop.get("value", "runtime")
    return meta


def _count_vulns(cdx):
    """Count vulnerabilities from enriched CycloneDX."""
    vulns = cdx.get("vulnerabilities", [])
    severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        ratings = v.get("ratings", [])
        sev = ratings[0].get("severity", "unknown").lower() if ratings else "unknown"
        if sev in severity_map:
            severity_map[sev] += 1
    return severity_map


def _compute_quality(cdx):
    """Quick heuristic quality score for Nix SBOMs (0-10 scale)."""
    score = 5.0
    components = cdx.get("components", [])
    total = len(components)

    if total == 0:
        return round(score, 2)

    # Nix SBOMs usually have hashes and PURLs
    with_hashes = sum(1 for c in components if c.get("hashes"))
    with_purl = sum(1 for c in components if c.get("purl"))
    with_lic = sum(1 for c in components if c.get("licenses"))

    # Integrity — hashes present
    score += (with_hashes / total) * 3.0
    # Identification — PURLs present
    score += (with_purl / total) * 1.5
    # Licensing
    score += (with_lic / total) * 0.5

    # Metadata quality
    meta = cdx.get("metadata", {})
    if meta.get("component", {}).get("name"):
        score += 1.0
    if meta.get("timestamp"):
        score += 0.5
    if meta.get("properties"):
        score += 0.5

    return round(min(score, 10.0), 2)


def _grade_from_score(score):
    """Map 0-10 score to A-F grade."""
    if score >= 9.0:
        return "A+"
    if score >= 8.0:
        return "A"
    if score >= 7.0:
        return "B"
    if score >= 6.0:
        return "C"
    if score >= 5.0:
        return "D"
    if score >= 4.0:
        return "E"
    return "F"


def build_explorer_manifest(cdx, product_id, variant, name=None):
    """Build an Explorer manifest entry dict from a sbomnix CycloneDX document."""
    meta = _nix_meta_from_cdx(cdx)
    sbom_type = meta.get("sbom_type", "runtime")
    component = cdx.get("metadata", {}).get("component", {})
    bom_name = component.get("name", "nix-package")
    bom_ver = component.get("version", "unknown")
    bom_desc = component.get("description", "")

    product_name = name or bom_name
    nix_specific = {}
    for prop in cdx.get("metadata", {}).get("properties", []):
        pname = prop.get("name", "")
        if pname.startswith("nixpkgs:") or pname == "sbom_type":
            nix_specific[pname] = prop.get("value", "")

    icon = "📦"
    if "firmware" in product_name.lower() or "linux" in product_name.lower():
        icon = "🔧"
    elif "app" in product_name.lower() or "gui" in product_name.lower():
        icon = "🖥️"
    elif "server" in product_name.lower() or "service" in product_name.lower():
        icon = "🌐"

    now_iso = datetime.now(timezone.utc).astimezone().isoformat()

    entry = {
        "id": product_id,
        "type": "nix",
        "icon": icon,
        "demo": False,
        "name": product_name,
        "tagline": {
            "en": bom_desc or f"Nix package: {bom_name}",
            "pl": f"Pakiet Nix: {bom_name}",
        },
        "variants": {
            variant: {
                "label": variant.capitalize(),
                "version": bom_ver,
                "date": now_iso[:10],
                "quality": {
                    "score": _compute_quality(cdx),
                    "grade": _grade_from_score(_compute_quality(cdx)),
                    "cats": {
                        "identification": 7.0,
                        "provenance": 5.0,
                        "integrity": 5.0,
                        "completeness": 6.0,
                        "licensing": 4.0,
                        "vulnerability": 5.0,
                        "structural": 8.0,
                        "sharing": 5.0,
                    },
                    "profiles": {
                        "ntia": "partial",
                        "bsi": "partial",
                        "fsct": "partial",
                    },
                },
                "components": _component_count(cdx),
                "vulns": _count_vulns(cdx),
                "sbom_type": sbom_type,
                "nix_meta": nix_specific,
            }
        },
        "evidence": {
            "scanner": {"tool": "sbomnix", "version": "1.x", "date": now_iso[:10]},
            "build_info": {},
        },
    }

    return entry


def write_explorer_product_json(outpath, cdx, product_id, variant, name=None):
    """Write a full Explorer product JSON file compatible with site/data/*.json."""
    entry = build_explorer_manifest(cdx, product_id, variant, name)
    outpath = Path(outpath)
    outpath.parent.mkdir(parents=True, exist_ok=True)
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2, ensure_ascii=False)
        f.write("\n")
    LOG.info("Wrote Explorer product JSON: %s", outpath)


def update_explorer_manifest(manifest_path, product_entry):
    """Add or replace a product entry in the Explorer manifest.json."""
    manifest_path = Path(manifest_path)
    manifest = {}
    if manifest_path.exists():
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    else:
        manifest["generated"] = datetime.now(timezone.utc).isoformat()
        manifest["products"] = []

    # Remove existing entry with same ID
    products = [p for p in manifest["products"] if p.get("id") != product_entry["id"]]
    products.append(product_entry)
    manifest["products"] = products
    manifest["generated"] = datetime.now(timezone.utc).isoformat()

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1, ensure_ascii=False)
        f.write("\n")
    LOG.info("Updated Explorer manifest: %s", manifest_path)


def explorify_cdx(cdx_path, explorer_dir, product_id, variant="nix", name=None):
    """Convert a sbomnix CycloneDX file into Explorer data files.

    Args:
        cdx_path: Path to sbomnix-generated CycloneDX JSON.
        explorer_dir: Root of SBOM Explorer (e.g. docs/ or site/). 
        product_id: Short URL-safe product identifier.
        variant: Variant key (e.g. 'linux', 'buildtime', 'runtime').
        name: Human-readable product name override.
    """
    cdx_path = Path(cdx_path)
    explorer_dir = Path(explorer_dir)
    with open(cdx_path, "r", encoding="utf-8") as f:
        cdx = json.load(f)

    # Write product data JSON
    product_json = explorer_dir / "data" / f"{product_id}.json"
    write_explorer_product_json(product_json, cdx, product_id, variant, name)

    # Update manifest
    manifest_path = explorer_dir / "data" / "manifest.json"
    entry = build_explorer_manifest(cdx, product_id, variant, name)
    update_explorer_manifest(manifest_path, entry)

    LOG.info("Explorify complete: product=%s variant=%s", product_id, variant)
