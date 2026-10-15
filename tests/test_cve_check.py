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
