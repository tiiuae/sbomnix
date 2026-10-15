#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Add EU vulnerability database (EUVD, ENISA) IDs to an SBOM Explorer product file.

    python scripts/euvd-enrich.py docs/data/demo-thermostat.json [--max 300]

For every CVE in each variant's `vuln_defs` that has no `euvd` yet, looks it up in EUVD and stores
{id, score, exploited, ...} under `euvd`. Lookups that fail are skipped and reported (re-run to fill them);
the file is only rewritten when something was added. EUVD has no CORS, so this runs at build time.
"""
import argparse, importlib.util, json, pathlib, sys

_spec = importlib.util.spec_from_file_location("cve_check", pathlib.Path(__file__).with_name("cve-check.py"))
cve_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cve_check)


def enrich(product, lookup=cve_check.euvd_lookup, limit=300):
    """Mutates `product`; returns (added, missing, failed)."""
    added = missing = failed = 0
    cache, todo = {}, 0
    for v in product.get("variants", {}).values():
        for cve, d in v.get("vuln_defs", {}).items():
            if not cve.startswith("CVE-") or "euvd" in d:
                continue
            if cve not in cache:
                if todo >= limit:
                    continue
                todo += 1
                try:
                    cache[cve] = lookup(cve)
                except Exception as e:
                    print(f"  ! {cve}: {e}", file=sys.stderr)
                    cache[cve] = Ellipsis
            r = cache[cve]
            if r is Ellipsis:
                failed += 1
            elif r:
                d["euvd"] = r
                added += 1
            else:
                d["euvd"] = None  # looked up, not in EUVD
                missing += 1
    return added, missing, failed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("product", help="docs/data/<id>.json")
    ap.add_argument("--max", type=int, default=300, help="max EUVD lookups per run (default 300)")
    a = ap.parse_args()
    path = pathlib.Path(a.product)
    product = json.loads(path.read_text())
    added, missing, failed = enrich(product, limit=a.max)
    if added or missing:
        path.write_text(json.dumps(product, indent=1, ensure_ascii=False) + "\n")
    print(f"{path.name}: {added} linked to EUVD, {missing} not in EUVD, {failed} failed/skipped")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
