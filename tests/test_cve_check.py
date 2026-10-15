# SPDX-License-Identifier: Apache-2.0
"""Reference SBOM + scripts/cve-check.py."""
import importlib.util
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SBOM = ROOT / "docs/reference-sbom/reference.cdx.json"


def _load():
    spec = importlib.util.spec_from_file_location("cve_check", ROOT / "scripts/cve-check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_reference_sbom_is_wellformed():
    bom = json.loads(SBOM.read_text())
    assert bom["bomFormat"] == "CycloneDX"
    refs = {c["bom-ref"] for c in bom["components"]}
    for c in bom["components"]:
        assert c["purl"].startswith("pkg:") and c["cpe"].startswith("cpe:2.3:")
        assert any(p["name"] == "expected-cve" for p in c["properties"])
    for d in bom["dependencies"]:
        assert set(d.get("dependsOn", [])) <= refs


@pytest.mark.network
def test_reference_sbom_against_live_databases(tmp_path, monkeypatch):
    mod = _load()
    monkeypatch.setattr("sys.argv", ["cve-check", str(SBOM), "--no-nvd", "--out", str(tmp_path / "r")])
    with pytest.raises(SystemExit) as e:
        mod.main()
    assert e.value.code == 0
    assert json.loads((tmp_path / "r.json").read_text())["self_test"] == "pass"


def test_euvd_enrich_with_stub_lookup():
    spec = importlib.util.spec_from_file_location("euvd_enrich", ROOT / "scripts/euvd-enrich.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    calls = []

    def lookup(cve):
        calls.append(cve)
        if cve == "CVE-2000-0002":
            return None
        if cve == "CVE-2000-0003":
            raise OSError("boom")
        return {"id": "EUVD-X", "score": "9.8", "exploited": True}

    product = {"variants": {"a": {"vuln_defs": {"CVE-2000-0001": {}, "CVE-2000-0002": {}, "CVE-2000-0003": {}, "GHSA-x": {}}},
                            "b": {"vuln_defs": {"CVE-2000-0001": {}, "CVE-2000-0009": {"euvd": {"id": "old"}}}}}}
    added, missing, failed = mod.enrich(product, lookup=lookup)
    assert (added, missing, failed) == (2, 1, 1)
    assert calls.count("CVE-2000-0001") == 1  # looked up once, reused across variants
    assert "CVE-2000-0009" not in calls and "GHSA-x" not in calls
    assert product["variants"]["b"]["vuln_defs"]["CVE-2000-0001"]["euvd"]["id"] == "EUVD-X"
    assert product["variants"]["a"]["vuln_defs"]["CVE-2000-0002"]["euvd"] is None
    assert "euvd" not in product["variants"]["a"]["vuln_defs"]["CVE-2000-0003"]
