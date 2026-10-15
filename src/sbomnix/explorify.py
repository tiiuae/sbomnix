#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Andrzej Piotrowski
#
# SPDX-License-Identifier: Apache-2.0

"""Convert sbomnix CycloneDX output into SBOM Explorer compatible JSON."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

try:
    from common.log import LOG
except ImportError:  # colorlog not installed (e.g. scripts/cve-check.py run with a bare python3)
    import logging

    LOG = logging.getLogger(__name__)


###############################################################################


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


DQ_STATES = ("osv", "nvd", "pending", "unmatched", "none")
SEVERITIES = ("critical", "high", "medium", "low", "unknown")


def _purl_type(purl):
    m = re.match(r"pkg:([^/]+)/", purl or "")
    return m.group(1) if m else "other"


def component_rows(cdx):
    """Explorer component rows [name, version, ecosystem, type, licence, licence class, CVE state, key] from a CycloneDX document.

    The CVE state is "pending" when the component has a purl or CPE that a scanner can look up, "none" otherwise.
    Licence classes are not derived here: a licence is "other", no licence is "unknown".
    """
    rows = []
    for c in cdx.get("components", []):
        lic = ", ".join(_extract_licenses(c))
        key = c.get("cpe") or c.get("purl") or ""
        rows.append([c.get("name", "?"), c.get("version", ""), _purl_type(c.get("purl")), "LIBRARY", lic,
                     "other" if lic else "unknown", "pending" if key else "none", key])
    return rows


def sbom_maturity(cdx, comps, method):
    """Maturity from what the SBOM itself shows; dimensions needing release history or process evidence are left out."""
    cs = cdx.get("components", [])
    pct = lambda f: round(100 * sum(1 for c in cs if f(c)) / max(1, len(cs)))
    cov = {"purl": pct(lambda c: c.get("purl")), "version": pct(lambda c: c.get("version")), "license": pct(lambda c: c.get("licenses")),
           "supplier": pct(lambda c: c.get("supplier")), "hash": pct(lambda c: c.get("hashes")),
           "cve": round(100 * sum(1 for c in comps if c[6] in ("osv", "nvd")) / max(1, len(comps)))}
    md = cdx.get("metadata", {})
    ntia = {"Supplier name": cov["supplier"] == 100, "Component name": all(c.get("name") for c in cs), "Component version": cov["version"] == 100,
            "Other unique identifiers (purl)": cov["purl"] == 100, "Dependency relationships": bool(cdx.get("dependencies")),
            "Author of SBOM data": bool(md.get("authors") or md.get("tools") or md.get("manufacture")), "Timestamp": bool(md.get("timestamp"))}
    dims = {"Inventory completeness": round((cov["purl"] + cov["version"]) / 2), "NTIA minimum elements": round(100 * sum(ntia.values()) / len(ntia)),
            "License compliance": cov["license"], "Integrity & provenance": cov["hash"]}
    w = method["weights"]
    score = round(sum(dims[k] * w[k] for k in dims) / sum(w[k] for k in dims))
    lv = next(lv for lv in method["levels"] if score < lv["below"])
    return {"score": score, "level": lv["level"], "level_name": lv["name"], "dims": dims, "ntia": ntia, "coverage": cov}


def sbom_block(cdx, fname):
    """The 'SBOM file' tab data for a CycloneDX document."""
    cs, md = cdx.get("components", []), cdx.get("metadata", {})
    subj = md.get("component", {})
    top = {k: (f"{len(v)} items" if isinstance(v, list) else "object" if isinstance(v, dict) else v) for k, v in cdx.items()}
    return {"file": fname, "format": "CycloneDX", "spec": f"CycloneDX-{cdx.get('specVersion')}", "serial": cdx.get("serialNumber"),
            "doc_version": cdx.get("version"), "timestamp": md.get("timestamp"), "tools": md.get("tools") or [],
            "subject": {"type": subj.get("type", "").upper(), "name": subj.get("name"), "version": subj.get("version"), "purl": subj.get("purl", "")},
            "top_level": top, "component_types": {"LIBRARY": sum(1 for c in cs if c.get("type") == "library")},
            "properties": {"purl": sum(1 for c in cs if c.get("purl")), "cpe": sum(1 for c in cs if c.get("cpe"))},
            "samples": {"generic": cs[0] if cs else {}}}


def assemble_product(cdx, product_id, variant, method, *, comps=None, defs=None, pairs=None, name=None, label=None, src_name="sbom.cdx.json",
                     file_path=None, product_type="software", icon="📦", demo=False, tagline=None, description=None, data_sources=None, today=None):
    """Build the full Explorer product (one variant, one release) and its manifest summary.

    comps/defs/pairs come from a scanner (scripts/cve-check.py); without them every component stays "pending lookup" and
    the CVE views are empty, which the UI reports as missing data rather than as "no vulnerabilities".
    Returns (product, manifest_entry).
    """
    comps = component_rows(cdx) if comps is None else comps
    defs, pairs = defs or {}, pairs or []
    meta = cdx.get("metadata", {}).get("component", {})
    ver, today = meta.get("version") or "unknown", today or datetime.now(timezone.utc).date().isoformat()
    name = name or meta.get("name") or product_id
    counts = dict.fromkeys(SEVERITIES, 0)
    for d in defs.values():
        counts[d.get("sev") if d.get("sev") in counts else "unknown"] += 1
    dq = {k: sum(1 for c in comps if c[6] == k) for k in DQ_STATES}
    eco = {}
    for c in comps:
        eco[c[2]] = eco.get(c[2], 0) + 1
    mat = sbom_maturity(cdx, comps, method)
    entry = {"version": ver, "date": today, "components": len(comps), "eco": eco, "licenses": {}, "vulns": counts, "vuln_total": len(defs),
             "vulns_open": counts, "open_total": len(defs), "dq": dq, "cve_pairs": pairs,
             "diff": {"added": [], "removed": [], "changed": []}, "diff_counts": {"added": 0, "removed": 0, "changed": 0},
             "maturity": {"score": mat["score"], "level": mat["level"]}, "files": []}
    var = {"label": label or variant.capitalize(), "history": [entry], "vuln_defs": defs, "components": comps, "maturity": mat,
           "sbom": sbom_block(cdx, src_name), "file_path": file_path or src_name, "upgrades": [], "process_actions": [], "data_gaps": [],
           "data_sources": data_sources or {}}
    nix_meta = _nix_meta_from_cdx(cdx)
    if nix_meta:
        var["nix_meta"] = nix_meta
    product = {"id": product_id, "type": product_type, "icon": icon, "demo": demo, "repo": None, "name": name,
               "tagline": tagline or {"en": meta.get("description") or f"SBOM of {name}", "pl": f"SBOM: {name}"},
               "description": description or {"en": "", "pl": ""}, "website": "", "links": [], "contact": {}, "repo_flags": {},
               "evidence_files": [], "compliance": None, "variants": {variant: var}}
    brief = {k: product[k] for k in ("id", "type", "icon", "demo", "name", "tagline")}
    brief["variants"] = {variant: {"label": var["label"], "version": ver, "date": today, "components": len(comps), "vulns": counts,
                                   "cve_checked": dq["osv"] + dq["nvd"], "dq": dq, "maturity": mat["score"], "level": mat["level"],
                                   "level_name": mat["level_name"], "releases": 1, "gaps": 0}}
    return product, brief


def write_explorer_files(explorer_dir, product, brief):
    """Write data/<id>.json and add or replace the product in data/manifest.json. Returns the manifest's method block."""
    data_dir = Path(explorer_dir) / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = data_dir / "manifest.json"
    manifest = {"products": []}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    (data_dir / f"{product['id']}.json").write_text(json.dumps(product, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    manifest["generated"] = datetime.now(timezone.utc).isoformat()
    manifest["products"] = [p for p in manifest.get("products", []) if p.get("id") != product["id"]] + [brief]
    manifest_path.write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    LOG.info("Wrote Explorer product %s and updated %s", data_dir / f"{product['id']}.json", manifest_path)


def explorer_method(explorer_dir):
    """The maturity weights and levels the Explorer's manifest.json defines."""
    path = Path(explorer_dir) / "data" / "manifest.json"
    if not path.exists():
        raise FileNotFoundError(f"{path} not found: --explorer-dir must point at the SBOM Explorer folder (docs/)")
    return json.loads(path.read_text(encoding="utf-8"))["method"]


def explorify_cdx(cdx_path, explorer_dir, product_id, variant="nix", name=None):
    """Add a sbomnix CycloneDX file to the SBOM Explorer as a product.

    No vulnerability lookups happen here, so every component with a purl or CPE shows as "pending lookup" in the Explorer.
    To fill in CVE, KEV, EPSS and EUVD data use scripts/cve-check.py with --explorer-product.

    Args:
        cdx_path: Path to sbomnix-generated CycloneDX JSON.
        explorer_dir: Root of SBOM Explorer (docs/).
        product_id: Short URL-safe product identifier.
        variant: Variant key (e.g. 'nix', 'buildtime', 'runtime').
        name: Human-readable product name override.
    """
    cdx_path = Path(cdx_path)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", product_id or ""):
        raise ValueError(f"invalid Explorer product id: {product_id!r} (use letters, digits, '.', '_' or '-')")
    cdx = json.loads(cdx_path.read_text(encoding="utf-8"))
    method = explorer_method(explorer_dir)
    product, brief = assemble_product(cdx, product_id, variant, method, name=name, src_name=cdx_path.name,
                                      product_type="software", icon="❄️", tagline=None)
    write_explorer_files(explorer_dir, product, brief)
    LOG.info("Explorify complete: product=%s variant=%s", product_id, variant)
