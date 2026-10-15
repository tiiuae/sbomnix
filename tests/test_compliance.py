# SPDX-License-Identifier: Apache-2.0
"""docs/compliance.js under node: licence classes (shared cases), policy, attribution notice, CycloneDX/SPDX/VEX export."""
import json
import pathlib
import re
import shutil
import subprocess

import pytest

from tests.testutils import validate_json

ROOT = pathlib.Path(__file__).resolve().parents[1]
RES = ROOT / "tests/resources"
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
TABLE = json.loads((ROOT / "docs/data/licenses.json").read_text())
CASES = json.loads((RES / "license_cases.json").read_text())
PRODUCT = json.loads((ROOT / "docs/data/cve-reference-app.json").read_text())
VARIANT = PRODUCT["variants"]["reference"]


def js(expr, **data):
    """Evaluate a JS expression with compliance.js as `c`; each keyword argument is a JSON variable (passed via stdin: products are big)."""
    code = (f"const c=require({json.dumps(str(ROOT / 'docs/compliance.js'))});const D=JSON.parse(require('fs').readFileSync(0,'utf8'));"
            f"const {{{','.join(data)}}}=D;process.stdout.write(JSON.stringify({expr}))") if data else (
        f"const c=require({json.dumps(str(ROOT / 'docs/compliance.js'))});process.stdout.write(JSON.stringify({expr}))")
    return json.loads(subprocess.run(["node", "-e", code], input=json.dumps(data), capture_output=True, text=True, check=True).stdout)


@pytest.mark.parametrize("case", CASES, ids=[str(c["expr"]) for c in CASES])
def test_license_class_matches_shared_cases(case):
    assert js("c.licenseClass(e,t)", e=case["expr"], t=TABLE) == case["class"]


def test_every_table_class_is_a_known_rank_or_class():
    assert set(TABLE["classes"].values()) <= set(TABLE["rank"]) | {"proprietary"}
    assert set(TABLE["obligations"]) >= set(TABLE["rank"]) | {"unknown"}


def rows_of(variant=VARIANT):
    return js("c.licenseRows(v,t)", v=variant, t=TABLE)


def test_license_rows_trust_old_class_only_without_licence_text():
    v = {"components": [["a", "1", "x", "LIBRARY", "", "permissive", "nvd", ""], ["b", "1", "x", "LIBRARY", "Weird", "permissive", "nvd", ""], ["c", "1", "x", "LIBRARY", "", "other", "nvd", ""]]}
    assert [r["cls"] for r in rows_of(v)] == ["permissive", "unknown", "unknown"]


def variant_with(licenses, cves=(), status="nvd"):
    comps = [[f"p{i}", "1", "x", "LIBRARY", lic, "unknown", status, ""] for i, lic in enumerate(licenses)]
    return {"components": comps, "vuln_defs": {c: d for c, _, d in cves},
            "history": [{"cve_pairs": [[c, "", "", lbl] for c, lbl, _ in cves]}]}


def policy(v, pol=None, stewards=None):
    return js("c.evalPolicy({rows:c.licenseRows(v,t),v,policy:p,stewards:s})", v=v, t=TABLE, p=pol, s=stewards)


def rule(res, rid):
    return next(r for r in res["rules"] if r["id"] == rid)


def test_policy_denies_strong_copyleft_by_default_and_flags_missing_licence():
    res = policy(variant_with(["MIT", "GPL-3.0-only", ""]))
    assert not res["pass"]
    assert rule(res, "licenseClass")["offenders"] == ["p1@1 (strong-copyleft: GPL-3.0-only)"]
    assert rule(res, "licenseMissing")["offenders"] == ["p2@1"]


def test_policy_passes_clean_permissive_product():
    assert policy(variant_with(["MIT", "Apache-2.0", "MIT OR GPL-3.0-only"]))["pass"]


def test_policy_kev_and_severity_rules():
    v = variant_with(["MIT"], [("CVE-1", "p0@1", {"kev": True, "sev": "critical"}), ("CVE-2", "p0@1", {"sev": "medium"}), ("CVE-3", "p0@1", {"sev": "high"})])
    res = policy(v)
    assert rule(res, "kev")["offenders"] == ["CVE-1 in p0@1"]
    assert sorted(o.split()[0] for o in rule(res, "severity")["offenders"]) == ["CVE-1", "CVE-3"]   # high and critical, not medium
    assert policy(v, {"failSeverity": "critical", "blockKev": False})["rules"][4]["offenders"] == ["CVE-1 (critical) in p0@1"]
    assert rule(policy(v, {"failSeverity": "off", "blockKev": False}), "severity")["skipped"]


def test_policy_does_not_treat_unchecked_as_clean():
    res = policy(variant_with(["MIT"], status="pending"))
    assert not res["pass"] and rule(res, "checked")["offenders"] == ["p0@1 (pending)"]
    assert policy(variant_with(["MIT"], status="pending"), {"requireChecked": False})["pass"]


def test_policy_denied_licence_list_and_steward_rule():
    res = policy(variant_with(["MIT", "Apache-2.0"]), {"denyLicenses": ["apache-2.0"]})
    assert rule(res, "licenseDenied")["offenders"] == ["p1@1 (Apache-2.0)"]
    v = variant_with(["MIT"], [("CVE-1", "p0@1", {"kev": True, "sev": "low"})])
    assert rule(policy(v, {"requireSteward": True, "blockKev": False}, {}), "steward")["offenders"] == ["p0@1 (no steward)"]
    assert rule(policy(v, {"requireSteward": True, "blockKev": False}, {"p0": "Team"}), "steward")["offenders"] == []
    assert rule(policy(v, {"requireSteward": True}, None), "steward")["skipped"]                    # CLI has no stewards: reported as skipped


def test_policy_on_real_reference_product():
    res = policy(VARIANT)
    assert not res["pass"]
    assert len(rule(res, "kev")["offenders"]) >= 2 and any("CVE-2021-44228" in o for o in rule(res, "kev")["offenders"])


def test_attribution_notice_groups_by_licence_and_warns_on_missing():
    rows = rows_of(variant_with(["MIT", "MIT", "", "GPL-3.0-only"]))
    text = js("c.attributionNotice({product:'Demo',version:'1.0',date:'2026-01-01',rows:r})", r=rows)
    assert "THIRD-PARTY NOTICES for Demo 1.0" in text
    assert text.index("\nGPL-3.0-only\n") < text.index("\nMIT\n") < text.index("\nNO LICENCE FOUND\n")   # sorted, missing licence listed
    assert text.count("  p0 1") == 1 and "WARNING: no licence was found" in text and "https://spdx.org/licenses/" in text


def test_cyclonedx_export_validates_against_schema(tmp_path):
    rows = rows_of()
    decisions = {"CVE-2021-44228": {"verdict": "trigger", "ts": "2026-10-15"}, "CVE-2020-8203": {"verdict": "not_affected", "ts": "2026-10-15"}}
    doc = js("c.toCycloneDX({product:'cve-reference-app',version:'1.0.0',rows:r,v,decisions:d})", r=rows, v=VARIANT, d=decisions)
    f = tmp_path / "x.cdx.json"
    f.write_text(json.dumps(doc))
    validate_json(f, RES / "cdx_bom-1.4.schema.json")
    refs = {c["bom-ref"] for c in doc["components"]}
    assert len(refs) == len(doc["components"]) == 4
    assert all(a["ref"] in refs for v in doc["vulnerabilities"] for a in v["affects"]) and len(doc["vulnerabilities"]) == 62
    by = {v["id"]: v for v in doc["vulnerabilities"]}
    assert by["CVE-2021-44228"]["analysis"]["state"] == "exploitable"
    assert by["CVE-2020-8203"]["analysis"] == {"state": "not_affected", "justification": "code_not_present", "detail": by["CVE-2020-8203"]["analysis"]["detail"]}
    assert by["CVE-2021-3711"]["analysis"]["state"] == "in_triage"                                  # no decision recorded: never invented
    assert any(p["name"] == "exploited-in-the-wild" for p in by["CVE-2021-44228"]["properties"])


def test_cyclonedx_without_vulns_and_with_duplicate_components(tmp_path):
    v = variant_with(["MIT", "MIT"])
    v["components"][1][0] = "p0"                                                                    # same name+version twice
    doc = js("c.toCycloneDX({product:'d',rows:c.licenseRows(v,t),v,withVulns:false})", v=v, t=TABLE)
    assert "vulnerabilities" not in doc and len({c["bom-ref"] for c in doc["components"]}) == 2
    f = tmp_path / "d.json"
    f.write_text(json.dumps(doc))
    validate_json(f, RES / "cdx_bom-1.4.schema.json")


def test_spdx_export_validates_against_schema(tmp_path):
    doc = js("c.toSPDX({product:'cve-reference-app',version:'1.0.0',rows:r})", r=rows_of())
    f = tmp_path / "x.spdx.json"
    f.write_text(json.dumps(doc))
    validate_json(f, RES / "spdx_bom-2.3.schema.json")
    ids = [p["SPDXID"] for p in doc["packages"]]
    assert len(ids) == len(set(ids)) == 5 and all(re.fullmatch(r"SPDXRef-[0-9A-Za-z.\-]+", i) for i in ids)
    assert all(r["relatedSpdxElement"] in ids for r in doc["relationships"])
    assert doc["packages"][1]["licenseDeclared"] == "Apache-2.0"                                      # log4j-core, from the SBOM
    nolic = js("c.toSPDX({product:'d',rows:r})", r=rows_of(variant_with([""])))
    assert nolic["packages"][1]["licenseDeclared"] == "NOASSERTION"                                  # no licence in the SBOM: not invented


def test_spdx_comma_lists_become_valid_expressions(tmp_path):
    v = variant_with(["MIT, BSD-3-Clause", "Custom thing"])
    doc = js("c.toSPDX({product:'d',rows:c.licenseRows(v,t)})", v=v, t=TABLE)
    assert doc["packages"][1]["licenseDeclared"] == "MIT AND BSD-3-Clause" and doc["packages"][2]["licenseDeclared"] == "NOASSERTION"
    from license_expression import get_spdx_licensing
    get_spdx_licensing().parse(doc["packages"][1]["licenseDeclared"], validate=True)


@pytest.mark.parametrize("dec,state", [(None, "in_triage"), ({"verdict": "not_affected"}, "not_affected"), ({"verdict": "incident"}, "exploitable"),
                                       ({"verdict": "trigger"}, "exploitable"), ({"verdict": "urgent"}, "in_triage"), ({"verdict": "routine"}, "in_triage")])
def test_vex_state_from_recorded_decision(dec, state):
    assert js("c.vexAnalysis(d)", d=dec)["state"] == state
