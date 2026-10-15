# SPDX-License-Identifier: Apache-2.0
"""sbomnix --explorer-dir: the product it writes must have the shape the SBOM Explorer UI reads."""
import json
import pathlib
import shutil

import pytest

from sbomnix.explorify import explorify_cdx

ROOT = pathlib.Path(__file__).resolve().parents[1]
CDX = ROOT / "docs/reference-sbom/reference.cdx.json"


@pytest.fixture
def site(tmp_path):
    (tmp_path / "data").mkdir()
    shutil.copy(ROOT / "docs/data/manifest.json", tmp_path / "data/manifest.json")
    return tmp_path


def _variant_keys(path):
    return set(next(iter(json.loads(path.read_text())["variants"].values())))


def test_product_has_every_key_the_ui_reads(site):
    explorify_cdx(CDX, site, "from-sbomnix", variant="nix", name="From sbomnix")
    product = json.loads((site / "data/from-sbomnix.json").read_text())
    var = product["variants"]["nix"]
    demo = _variant_keys(ROOT / "docs/data/demo-thermostat.json")
    # keys the UI dereferences on every product page (a missing one shows "Could not load data")
    assert {"history", "vuln_defs", "components", "maturity", "sbom", "upgrades", "process_actions", "data_gaps", "data_sources", "file_path"} <= set(var)
    assert (demo - {"quality", "scanners"}) <= set(var) | {"label"}
    entry = var["history"][0]
    assert {"version", "date", "components", "eco", "licenses", "vulns", "vuln_total", "vulns_open", "open_total", "dq", "cve_pairs", "diff", "diff_counts", "maturity", "files"} <= set(entry)
    assert {"dims", "ntia", "coverage", "level_name"} <= set(var["maturity"])
    assert {"file", "format", "spec", "top_level", "subject", "samples"} <= set(var["sbom"])
    assert product["name"] == "From sbomnix" and product["type"] == "software"


def test_no_scanner_means_pending_not_clean(site):
    explorify_cdx(CDX, site, "p", variant="nix")
    var = json.loads((site / "data/p.json").read_text())["variants"]["nix"]
    assert all(c[6] == "pending" for c in var["components"])          # purl/CPE present, nobody looked them up
    assert var["history"][0]["dq"]["pending"] == len(var["components"]) and var["history"][0]["vuln_total"] == 0
    assert "quality" not in var                                       # no invented quality score
    brief = next(p for p in json.loads((site / "data/manifest.json").read_text())["products"] if p["id"] == "p")
    assert brief["variants"]["nix"]["cve_checked"] == 0               # the UI must not claim CVE coverage


def test_components_without_identifiers_are_none(site, tmp_path):
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"type": "library", "name": "mystery", "version": "1"}]}
    f = tmp_path / "x.cdx.json"
    f.write_text(json.dumps(cdx))
    explorify_cdx(f, site, "x")
    assert json.loads((site / "data/x.json").read_text())["variants"]["nix"]["components"][0][6] == "none"


def test_rerun_replaces_product_and_keeps_others(site):
    explorify_cdx(CDX, site, "a")
    explorify_cdx(CDX, site, "b")
    explorify_cdx(CDX, site, "a", name="Renamed")
    ids = [p["id"] for p in json.loads((site / "data/manifest.json").read_text())["products"]]
    assert ids.count("a") == 1 and ids.count("b") == 1 and "demo-thermostat" in ids
    assert next(p for p in json.loads((site / "data/manifest.json").read_text())["products"] if p["id"] == "a")["name"] == "Renamed"


@pytest.mark.parametrize("bad", ["../evil", "a/b", "", ".hidden", "x y"])
def test_rejects_unsafe_product_id(site, bad):
    with pytest.raises(ValueError):
        explorify_cdx(CDX, site, bad)
    assert not list((site / "data").glob("*evil*")) and not (site.parent / "evil.json").exists()


def test_wrong_directory_gives_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="must point at the SBOM Explorer folder"):
        explorify_cdx(CDX, tmp_path, "p")


LIC_CASES = json.loads((ROOT / "tests/resources/license_cases.json").read_text())
LIC_TABLE = json.loads((ROOT / "docs/data/licenses.json").read_text())


@pytest.mark.parametrize("case", LIC_CASES, ids=[str(c["expr"]) for c in LIC_CASES])
def test_license_class(case):
    from sbomnix.explorify import license_class
    assert license_class(case["expr"], LIC_TABLE) == case["class"]


def test_explorify_classifies_licenses_when_table_present(site, tmp_path):
    shutil.copy(ROOT / "docs/data/licenses.json", site / "data/licenses.json")
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "a", "version": "1", "purl": "pkg:pypi/a@1", "licenses": [{"license": {"id": "MIT"}}]},
        {"type": "library", "name": "b", "version": "1", "purl": "pkg:pypi/b@1", "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
        {"type": "library", "name": "c", "version": "1", "purl": "pkg:pypi/c@1"}]}
    f = tmp_path / "l.cdx.json"
    f.write_text(json.dumps(cdx))
    explorify_cdx(f, site, "lic")
    var = json.loads((site / "data/lic.json").read_text())["variants"]["nix"]
    assert [c[5] for c in var["components"]] == ["permissive", "strong-copyleft", "unknown"]
    assert var["history"][0]["licenses"] == {"permissive": 1, "strong-copyleft": 1, "unknown": 1}


def test_expression_licenses_are_read(site, tmp_path):
    shutil.copy(ROOT / "docs/data/licenses.json", site / "data/licenses.json")
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "e", "version": "1", "licenses": [{"expression": "MIT OR GPL-3.0-only"}]},
        {"type": "library", "name": "n", "version": "1", "licenses": [{"license": {"name": "Custom thing"}}]}]}
    f = tmp_path / "e.cdx.json"
    f.write_text(json.dumps(cdx))
    explorify_cdx(f, site, "expr")
    comps = json.loads((site / "data/expr.json").read_text())["variants"]["nix"]["components"]
    assert comps[0][4] == "MIT OR GPL-3.0-only" and comps[0][5] == "permissive"
    assert comps[1][4] == "Custom thing" and comps[1][5] == "unknown"   # a licence name we cannot map is unknown, not clean
