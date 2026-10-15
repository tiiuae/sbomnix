# SPDX-License-Identifier: Apache-2.0
"""docs/library.js under node: SBOM import (CycloneDX, SPDX), product building (parity with sbomnix explorify), CVSS and the vulnerability check with the network mocked."""
import json
import pathlib
import shutil
import subprocess

import pytest

from sbomnix.explorify import assemble_product
from tests.testutils import validate_json

ROOT = pathlib.Path(__file__).resolve().parents[1]
RES = ROOT / "tests/resources"
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
TABLE = json.loads((ROOT / "docs/data/licenses.json").read_text())
METHOD = json.loads((ROOT / "docs/data/manifest.json").read_text())["method"]
REF_CDX = json.loads((ROOT / "docs/reference-sbom/reference.cdx.json").read_text())

HARNESS = r"""
const fs = require('fs');
const lib = require(process.argv[1] + '/docs/library.js'), comp = require(process.argv[1] + '/docs/compliance.js'), ir = require(process.argv[1] + '/docs/ir.js');
const D = JSON.parse(fs.readFileSync(0, 'utf8'));
(async () => {
  const mockFetch = D.net ? async (url, init) => {
    const u = String(url), calls = (globalThis.__calls = globalThis.__calls || []); calls.push({url: u, method: (init && init.method) || 'GET'});
    for (const [pat, r] of D.net) if (u.includes(pat)) { if (r.throw) throw new Error(r.throw); return {ok: r.status === undefined || r.status < 400, status: r.status || 200, json: async () => r.body}; }
    return {ok: false, status: 404, json: async () => ({})};
  } : null;
  const out = await (new Function('lib', 'comp', 'ir', 'D', 'mockFetch', 'return (async () => (' + D.expr + '))()'))(lib, comp, ir, D, mockFetch);
  process.stdout.write(JSON.stringify({value: out, calls: globalThis.__calls || []}));
})().catch(e => { process.stdout.write(JSON.stringify({error: String(e && e.message || e)})); });
"""


def js(expr, **data):
    p = subprocess.run(["node", "-e", HARNESS, str(ROOT)], input=json.dumps({"expr": expr, **data}), capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def ok(expr, **data):
    r = js(expr, **data)
    assert "error" not in r, r["error"]
    return r["value"]


def err(expr, **data):
    r = js(expr, **data)
    assert "error" in r, "expected an error, got " + json.dumps(r)[:200]
    return r["error"]


# ---------------------------------------------------------------- parsing
def test_cyclonedx_normalised_with_nested_components_and_dependencies():
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"bom-ref": "root", "name": "app", "version": "2", "type": "application"}, "tools": [{"name": "t"}], "timestamp": "2026-01-01T00:00:00Z"},
           "components": [{"bom-ref": "a", "name": "a", "version": "1", "type": "library", "purl": "pkg:npm/a@1", "licenses": [{"license": {"id": "MIT"}}], "supplier": {"name": "ACME"},
                           "hashes": [{"alg": "SHA-1", "content": "x"}], "components": [{"bom-ref": "a1", "name": "inner", "version": "9"}]},
                          {"bom-ref": "b", "name": "b", "version": "2", "cpe": "cpe:2.3:a:v:b:2:*:*:*:*:*:*:*", "licenses": [{"expression": "MIT OR GPL-3.0-only"}], "publisher": "Pub Inc"}],
           "dependencies": [{"ref": "root", "dependsOn": ["a", "b"]}, {"ref": "b", "dependsOn": ["a", "ghost"]}, {"ref": "ghost-source", "dependsOn": ["a"]}]}
    n = ok("lib.libNormalize(D.doc)", doc=doc)
    assert (n["format"], n["name"], n["version"], n["spec"]) == ("CycloneDX", "app", "2", "CycloneDX-1.5")
    assert [c["name"] for c in n["components"]] == ["a", "inner", "b"]                       # nested components are flattened
    assert n["components"][0]["license"] == "MIT" and n["components"][0]["supplier"] == "ACME" and n["components"][0]["hashes"] is True
    assert n["components"][2]["license"] == "MIT OR GPL-3.0-only" and n["components"][2]["supplier"] == "Pub Inc"       # publisher is the fallback supplier
    assert sorted(n["edges"]) == sorted([[0, 1], [-1, 0], [-1, 2], [2, 0]])                  # nested = parent -> child; unknown refs are dropped, not invented
    assert n["hasAuthor"] is True and n["hasDependencies"] is True


def test_spdx_normalised_relationship_variants():
    doc = {"spdxVersion": "SPDX-2.3", "name": "doc", "documentNamespace": "https://x/1", "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: x"]}, "documentDescribes": ["SPDXRef-Root"],
           "packages": [{"SPDXID": "SPDXRef-Root", "name": "app", "versionInfo": "3"},
                        {"SPDXID": "SPDXRef-A", "name": "a", "versionInfo": "1", "licenseDeclared": "NOASSERTION", "licenseConcluded": "Apache-2.0", "supplier": "Organization: ACME Corp",
                         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/a@1"}], "checksums": [{"algorithm": "SHA1", "checksumValue": "x"}]},
                        {"SPDXID": "SPDXRef-B", "name": "b", "supplier": "NOASSERTION", "externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:v:b:*:*:*:*:*:*:*:*"}]},
                        {"SPDXID": "SPDXRef-C", "name": "c"}],
           "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Root"},
                             {"spdxElementId": "SPDXRef-Root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-A"},
                             {"spdxElementId": "SPDXRef-B", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-Root"},     # B is a dependency of Root: Root -> B
                             {"spdxElementId": "SPDXRef-A", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-C"},
                             {"spdxElementId": "SPDXRef-B", "relationshipType": "CONTAINED_BY", "relatedSpdxElement": "SPDXRef-A"}]}  # A contains B
    n = ok("lib.libNormalize(D.doc)", doc=doc)
    assert (n["format"], n["name"], n["version"]) == ("SPDX", "app", "3") and [c["name"] for c in n["components"]] == ["a", "b", "c"]      # the described root is not a component
    a, b, c = n["components"]
    assert a["license"] == "Apache-2.0" and a["supplier"] == "ACME Corp" and a["purl"] == "pkg:pypi/a@1" and a["hashes"] is True      # concluded when declared is NOASSERTION
    assert b["cpe"].startswith("cpe:2.3:a:v:b") and b["supplier"] == "" and c["license"] == ""
    assert sorted(n["edges"]) == sorted([[-1, 0], [-1, 1], [0, 2], [0, 1]])


@pytest.mark.parametrize("bad,needle", [("", "empty"), ("   \n", "empty"), ("<bom></bom>", "XML is not supported"), ("SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0", "tag-value"),
                                        ("{not json", "not valid JSON"), ("[1,2]", "not a CycloneDX or SPDX"), ('{"hello": 1}', "not a CycloneDX or SPDX"), ('{"spdxVersion": "SPDX-2.3"}', "not a CycloneDX or SPDX"),
                                        ('"just a string"', "not a CycloneDX or SPDX"), ("null", "not a CycloneDX or SPDX")])
def test_bad_input_gets_a_clear_message(bad, needle):
    assert needle in err("lib.libNormalize(D.text)", text=bad)


def test_component_limit():
    doc = {"bomFormat": "CycloneDX", "components": [{"name": "x"}] * 20001}
    assert "too many components" in err("lib.libNormalize(D.doc)", doc=doc)
    assert len(ok("lib.libNormalize(D.doc).components", doc={"bomFormat": "CycloneDX", "components": [{"name": "x"}] * 20000})) == 20000


def test_garbage_inside_a_valid_document_does_not_crash():
    doc = {"bomFormat": "CycloneDX", "components": [None, 5, "x", {"name": None, "version": 3, "purl": 7, "licenses": "MIT", "supplier": "str"}, {"name": "ok"}], "dependencies": "nope", "metadata": []}
    n = ok("lib.libNormalize(D.doc)", doc=doc)
    assert [c["name"] for c in n["components"]] == ["?", "ok"] and n["components"][0]["purl"] == "" and n["edges"] == []


# ---------------------------------------------------------------- building
def build(doc, **kw):
    return ok("lib.libBuildProduct(lib.libNormalize(D.doc), {id: D.id, method: D.method, table: D.table, today: '2026-01-01', ...D.opts})", doc=doc, id="local-x", method=METHOD, table=TABLE, opts=kw)


def test_product_has_every_key_the_ui_reads():
    r = build(REF_CDX, name="Mine", origin="third-party", sourceLabel="ACME Corp", srcName="ref.cdx.json")
    p, v = r["product"], next(iter(r["product"]["variants"].values()))
    demo = set(next(iter(json.loads((ROOT / "docs/data/demo-thermostat.json").read_text())["variants"].values())))
    assert (demo - {"quality", "scanners"}) <= set(v) | {"label"} and {"graph", "sbom", "maturity", "history", "vuln_defs", "components"} <= set(v)
    e = v["history"][0]
    assert {"version", "date", "components", "eco", "licenses", "vulns", "vuln_total", "vulns_open", "open_total", "dq", "cve_pairs", "diff", "diff_counts", "maturity", "files"} <= set(e)
    assert p["name"] == "Mine" and p["origin"] == "third-party" and p["source_label"] == "ACME Corp" and "ACME Corp" in p["tagline"]["en"] and p["local"] is True and p["demo"] is False
    assert r["brief"]["id"] == "local-x" and r["brief"]["local"] is True and r["brief"]["variants"]["imported"]["cve_checked"] == 0


def test_nothing_looked_up_is_pending_never_clean():
    v = next(iter(build(REF_CDX)["product"]["variants"].values()))
    assert all(c[6] == "pending" for c in v["components"]) and v["history"][0]["dq"]["pending"] == 4 and v["history"][0]["vuln_total"] == 0 and "quality" not in v
    assert v["maturity"]["coverage"]["cve"] == 0 and v["data_sources"] == {}


def test_parity_with_the_python_builder():
    """The same SBOM must give the same product from sbomnix explorify (Python) and from the browser import (JS)."""
    py_product, py_brief = assemble_product(REF_CDX, "local-x", "imported", METHOD, license_table=TABLE, today="2026-01-01", src_name="ref.cdx.json")
    r = build(REF_CDX, srcName="ref.cdx.json")
    pv, jv = py_product["variants"]["imported"], r["product"]["variants"]["imported"]
    assert [c[:9] for c in jv["components"]] == [c[:9] for c in pv["components"]]               # name, version, eco, type, licence, class, state, key, supplier
    assert jv["graph"] == pv["graph"] and jv["maturity"] == pv["maturity"]
    assert jv["history"][0]["eco"] == pv["history"][0]["eco"] and jv["history"][0]["licenses"] == pv["history"][0]["licenses"] and jv["history"][0]["dq"] == pv["history"][0]["dq"]
    for k in ("file", "format", "spec", "serial", "doc_version", "timestamp", "subject", "top_level", "component_types", "properties"):
        assert jv["sbom"][k] == pv["sbom"][k], k
    jb, pb = r["brief"]["variants"]["imported"], py_brief["variants"]["imported"]
    assert {k: jb[k] for k in pb} == pb


def test_licence_classes_and_unknowns_in_imported_rows():
    doc = {"bomFormat": "CycloneDX", "components": [{"name": "a", "licenses": [{"license": {"id": "GPL-3.0-only"}}]}, {"name": "b"}, {"name": "c", "licenses": [{"license": {"name": "Weird"}}]}]}
    v = next(iter(build(doc)["product"]["variants"].values()))
    assert [c[5] for c in v["components"]] == ["strong-copyleft", "unknown", "unknown"] and v["history"][0]["licenses"] == {"strong-copyleft": 1, "unknown": 2}
    assert [c[6] for c in v["components"]] == ["none", "none", "none"]                          # no purl / CPE: nothing a scanner can look up


def test_imported_product_works_with_the_rest_of_the_explorer(tmp_path):
    """Policy, supply chain, export and the schema all accept an imported product (no CVE data yet)."""
    p = build(REF_CDX)["product"]
    v = next(iter(p["variants"].values()))
    res = ok("comp.evalPolicy({rows: comp.licenseRows(D.v, D.t), v: D.v, policy: {}, stewards: null})", v=v, t=TABLE)
    assert {r["id"]: r for r in res["rules"]}["checked"]["pass"] is False                      # unchecked components fail the policy
    doc = ok("comp.toCycloneDX({product: 'x', rows: comp.licenseRows(D.v, D.t), v: D.v})", v=v, t=TABLE)
    f = tmp_path / "x.cdx.json"
    f.write_text(json.dumps(doc))
    validate_json(f, RES / "cdx_bom-1.4.schema.json")


def test_our_own_spdx_export_can_be_imported_again():
    prod = json.loads((ROOT / "docs/data/cve-reference-app.json").read_text())["variants"]["reference"]
    spdx = ok("comp.toSPDX({product: 'rt', version: '1', rows: comp.licenseRows(D.v, D.t)})", v=prod, t=TABLE)
    n = ok("lib.libNormalize(D.doc)", doc=spdx)
    assert n["format"] == "SPDX" and n["name"] == "rt" and [c["name"] for c in n["components"]] == [c[0] for c in prod["components"]]
    assert [c["license"] for c in n["components"]] == ["Apache-2.0", "Apache-2.0", "MIT", "OpenSSL"] and all(c["purl"] or c["cpe"] for c in n["components"])
    assert len(n["edges"]) == 4 and all(e[0] == -1 for e in n["edges"])


def test_slug():
    assert ok("lib.libSlug(D.s)", s="My App v1.2!") == "my-app-v1.2" and ok("lib.libSlug(D.s)", s="") == "sbom" and ok("lib.libSlug(D.s)", s="../../etc") == "etc"
    assert len(ok("lib.libSlug(D.s)", s="x" * 200)) == 40


# ---------------------------------------------------------------- CVSS and OSV severity
@pytest.mark.parametrize("vec,score,sev", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),     # Log4Shell
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4, "medium"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, "low"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "unknown"),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H", 10.0, "critical"),   # temporal metrics are ignored
    ("CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L", 5.9, "medium"),      # by hand: expl 1.668, impact 3.733, 1.08*(3.733+1.668)=5.83 -> 5.9
])
def test_cvss3_base_scores(vec, score, sev):
    assert ok("lib.libCvss3(D.v)", v=vec) == {"score": score, "severity": sev}


@pytest.mark.parametrize("vec", ["", None, "AV:N/AC:L", "CVSS:2.0/AV:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H"])
def test_cvss3_rejects_incomplete_or_other_versions(vec):
    assert ok("lib.libCvss3(D.v)", v=vec) is None


def test_osv_severity_prefers_vector_then_database_word_then_unknown():
    s = lambda rec: ok("lib.libOsvSeverity(D.r)", r=rec)
    assert s({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}], "database_specific": {"severity": "LOW"}})["sev"] == "critical"
    assert s({"database_specific": {"severity": "MODERATE"}}) == {"sev": "medium", "score": None, "vector": None}
    assert s({"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/..."}], "database_specific": {"severity": "HIGH"}})["sev"] == "high"
    assert s({})["sev"] == "unknown" and s(None)["sev"] == "unknown" and s({"database_specific": {"severity": "weird"}})["sev"] == "unknown"


# ---------------------------------------------------------------- the vulnerability check, network mocked
def purl_doc():
    return {"bomFormat": "CycloneDX", "specVersion": "1.4", "metadata": {"component": {"name": "app", "version": "1"}}, "components": [
        {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
        {"name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0"},
        {"name": "openssl", "version": "1.1.1k", "purl": "pkg:generic/openssl@1.1.1k"},
        {"name": "nvdonly", "version": "1", "cpe": "cpe:2.3:a:v:nvdonly:1:*:*:*:*:*:*:*"},
        {"name": "mystery", "version": "1"}]}


LOG4SHELL = {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"], "summary": "Remote code injection in Log4j", "published": "2021-12-10T00:40:56Z",
             "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]}
NOCVE = {"id": "GHSA-aaaa-bbbb-cccc", "aliases": [], "details": "# Heading\n\nSomething bad happens in requests.", "published": "2020-01-01T00:00:00Z", "database_specific": {"severity": "MODERATE"}}
NET = [["/v1/querybatch", {"body": {"results": [{"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q"}]}, {"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}]}}],
       ["/v1/vulns/GHSA-jfh8", {"body": LOG4SHELL}], ["/v1/vulns/GHSA-aaaa", {"body": NOCVE}],
       ["known_exploited", {"body": {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known"}]}}],
       ["epss", {"body": {"data": [{"cve": "CVE-2021-44228", "epss": "0.99999"}]}}],
       ["PoC/2021/CVE-2021-44228.json", {"body": [{"html_url": "https://github.com/x/poc"}, {"html_url": "https://github.com/y/poc"}]}]]
DEPS = "{fetch: mockFetch, osv: 'https://osv.test', kevUrl: 'https://kev.test/known_exploited.json', epssUrl: 'https://epss.test/epss', pocBase: 'https://poc.test/PoC', today: '2026-02-02'}"


def enrich(net=NET, doc=None, **kw):
    expr = f"lib.libEnrich(lib.libBuildProduct(lib.libNormalize(D.doc), {{id: 'local-x', method: D.method, table: D.table, today: '2026-01-01'}}).product, {DEPS})"
    return js(expr, doc=doc or purl_doc(), method=METHOD, table=TABLE, net=net, **kw)


def test_enrich_end_to_end():
    r = enrich()
    assert "error" not in r, r
    res, calls = r["value"], r["calls"]
    v = next(iter(res["product"]["variants"].values()))
    assert [c[6] for c in v["components"]] == ["osv", "osv", "unmatched", "pending", "none"]                 # looked up / looked up / ecosystem not covered / CPE only / nothing
    defs = v["vuln_defs"]
    assert set(defs) == {"CVE-2021-44228", "GHSA-aaaa-bbbb-cccc"}                                              # keyed by CVE when there is one
    d = defs["CVE-2021-44228"]
    assert d["sev"] == "critical" and d["score"] == 10.0 and d["kev"] is True and d["kev_info"] == {"date": "2021-12-10", "ransomware": True} and d["kev_src"] == ["cisa"]
    assert d["epss"] == 0.99999 and d["poc"] == {"n": 2, "url": "https://github.com/x/poc"} and d["osv"] == "GHSA-jfh8-c2jp-5v3q" and d["published"] == "2021-12-10"
    g = defs["GHSA-aaaa-bbbb-cccc"]
    assert g["sev"] == "medium" and g["score"] is None and g["summary"] == "Something bad happens in requests." and g["kev"] is False and "poc" not in g     # no CVE id: no KEV/EPSS/PoC lookup possible
    e = v["history"][0]
    assert sorted(p[3] for p in e["cve_pairs"]) == ["log4j-core@2.14.1", "requests@2.19.0"] and e["vulns"]["critical"] == 1 and e["vulns"]["medium"] == 1 and e["vuln_total"] == 2
    assert e["dq"] == {"osv": 2, "nvd": 0, "pending": 1, "unmatched": 1, "none": 1}
    assert res["brief"]["variants"]["imported"]["cve_checked"] == 2 and res["product"]["checked"] == "2026-02-02"
    assert v["data_sources"] == {"osv_asof": "2026-02-02", "kev_day": "2026-02-02", "epss_asof": "2026-02-02", "poc_asof": "2026-02-02"}
    assert res["stats"]["kev"] == 1 and res["stats"]["cves"] == 2
    assert sum("querybatch" in c["url"] for c in calls) == 1                                                   # one batched OSV query, not one per component


def test_enriched_product_feeds_the_incident_tiers():
    r = enrich()["value"]
    v = next(iter(r["product"]["variants"].values()))
    tiers = ok("D.f.map(x => ({cve: x[0], tier: ir.irTier(D.defs[x[0]])}))", f=v["history"][0]["cve_pairs"], defs=v["vuln_defs"])
    assert {t["cve"]: t["tier"] for t in tiers} == {"CVE-2021-44228": "kev", "GHSA-aaaa-bbbb-cccc": "routine"}


def test_osv_failure_aborts_without_partial_data():
    for bad in ({"status": 500}, {"throw": "offline"}):
        r = enrich([["/v1/querybatch", bad]])
        assert "error" in r and "OSV" in r["error"]


def test_kev_failure_aborts_because_not_in_kev_would_otherwise_be_a_lie():
    for bad in ({"status": 503}, {"body": {"vulnerabilities": []}}, {"throw": "x"}):
        net = [n for n in NET if n[0] != "known_exploited"] + [["known_exploited", bad]]
        r = enrich(net)
        assert "error" in r and "KEV" in r["error"], r


def test_epss_failure_aborts():
    r = enrich([n for n in NET if n[0] != "epss"] + [["epss", {"status": 429}]])
    assert "error" in r and "EPSS" in r["error"]


def test_poc_failure_leaves_the_key_absent_but_404_means_none():
    net = [n for n in NET if "PoC/" not in n[0]] + [["PoC/2021/CVE-2021-44228.json", {"status": 500}]]
    d = next(iter(enrich(net)["value"]["product"]["variants"].values()))["vuln_defs"]["CVE-2021-44228"]
    assert "poc" not in d                                                                                          # unknown, shown as "?" - not "no PoC"
    net404 = [n for n in NET if "PoC/" not in n[0]]                                                                # mock default is 404
    assert next(iter(enrich(net404)["value"]["product"]["variants"].values()))["vuln_defs"]["CVE-2021-44228"]["poc"] is None


def test_missing_vulnerability_details_are_counted_not_hidden():
    net = [n for n in NET if "GHSA-aaaa" not in n[0]]                                                              # details for one id answer 404
    v = next(iter(enrich(net)["value"]["product"]["variants"].values()))
    assert set(v["vuln_defs"]) == {"CVE-2021-44228"} and v["data_gaps"] == [{"id": "missing_details", "n": 1}]


def test_too_many_vulnerabilities_are_capped_and_the_cap_is_reported():
    ids = [f"GHSA-{i:04d}-xxxx-yyyy" for i in range(305)]
    net = [["/v1/querybatch", {"body": {"results": [{"vulns": [{"id": i} for i in ids]}, {"vulns": []}]}}]] + \
          [["/v1/vulns/", {"body": {"id": "x", "aliases": [], "database_specific": {"severity": "LOW"}}}]] + [n for n in NET if n[0] in ("known_exploited", "epss")]
    r = enrich(net)
    assert "error" not in r, r
    v = next(iter(r["value"]["product"]["variants"].values()))
    assert len(v["vuln_defs"]) <= 300 and r["value"]["stats"]["truncated"] == 5 and {"id": "truncated", "n": 5} in v["data_gaps"]


def test_enrich_does_not_modify_its_input_and_sends_only_purls_to_osv():
    r = js(f"(async () => {{ const b = lib.libBuildProduct(lib.libNormalize(D.doc), {{id: 'local-x', method: D.method, table: D.table, today: '2026-01-01'}}).product; const before = JSON.stringify(b); "
           f"let sent = null; const f = async (u, i) => {{ if (String(u).includes('querybatch')) sent = JSON.parse(i.body); return mockFetch(u, i); }}; "
           f"await lib.libEnrich(b, {{...{DEPS}, fetch: f}}); return {{same: before === JSON.stringify(b), sent}}; }})()", doc=purl_doc(), method=METHOD, table=TABLE, net=NET)
    assert r["value"]["same"] is True
    assert [q["package"]["purl"] for q in r["value"]["sent"]["queries"]] == ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:pypi/requests@2.19.0"]     # no generic, no CPE-only, no names


def test_age_days():
    age = lambda ds: ok("lib.libAgeDays({data_sources: D.ds}, Date.parse('2026-02-20'))", ds=ds)
    assert age({"osv_asof": "2026-02-10", "kev_day": "2026-02-01", "other": "2020-01-01"}) == 19                      # oldest source counts, unrelated keys do not
    assert age({}) is None and age({"x": "nope"}) is None
