# SPDX-License-Identifier: Apache-2.0
"""IR triage classifier (docs/ir.js) run under node."""
import json
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def run_js(expr):
    code = f"const ir=require({json.dumps(str(ROOT / 'docs/ir.js'))});process.stdout.write(JSON.stringify({expr}))"
    return json.loads(subprocess.run(["node", "-e", code], capture_output=True, text=True, check=True).stdout)


@pytest.mark.parametrize("d,tier", [
    ({"kev": True, "epss": 0.99, "poc": {"n": 457}}, "kev"),
    ({"kev": True}, "kev"),                                   # KEV alone is enough
    ({"kev": False, "poc": {"n": 1}, "epss": 0.0}, "poc"),     # PoC beats a low EPSS
    ({"kev": False, "poc": {"n": 3}, "epss": 0.9}, "poc"),     # PoC tier wins over likely
    ({"kev": False, "poc": None, "epss": 0.10}, "likely"),     # boundary: exactly 0.10
    ({"kev": False, "poc": None, "epss": 0.0999}, "routine"),
    ({"kev": False, "poc": {"n": 0}, "epss": 0.05}, "routine"),  # empty PoC list is no PoC
    ({}, "routine"),                                           # no data never raises a tier
    (None, "routine"),
    ({"epss": "0.9"}, "routine"),                              # non-numeric EPSS ignored
])
def test_tier(d, tier):
    assert run_js(f"ir.irTier({json.dumps(d)})") == tier


def test_explain_reasons():
    d = {"kev": True, "kev_src": ["cisa", "euvd"], "kev_info": {"date": "2021-12-10", "ransomware": True}, "poc": {"n": 457, "url": "u"}, "epss": 0.99999}
    out = run_js(f"ir.irExplain({json.dumps(d)})")
    assert [x["k"] for x in out] == ["kev", "poc", "epss"]
    assert out[0]["ransomware"] is True and out[0]["date"] == "2021-12-10" and out[1]["n"] == 457
    assert run_js("ir.irExplain(null)") == []


def test_reference_product_tiers():
    """Real data: the demo product must contain exactly the shape the tiers promise."""
    defs = json.loads((ROOT / "docs/data/cve-reference-app.json").read_text())["variants"]["reference"]["vuln_defs"]
    tiers = {c: run_js(f"ir.irTier({json.dumps(d)})") for c, d in defs.items()}
    assert tiers["CVE-2021-44228"] == "kev" and tiers["CVE-2021-45046"] == "kev"
    assert tiers["CVE-2020-8203"] == "routine"          # lodash: not KEV, no PoC, low EPSS
    assert tiers["CVE-2021-3711"] == "likely"           # openssl: not KEV, no PoC, EPSS .878
    assert {"kev", "poc", "likely", "routine"} <= set(tiers.values())


@pytest.mark.parametrize("a,verdict,prio", [
    ({"tier": "kev", "deployed": "yes", "exposed": "yes"}, "trigger", "P1"),            # KEV + deployed + reachable: trigger, NOT incident
    ({"tier": "kev", "deployed": "yes", "exposed": "no"}, "urgent", "P2"),
    ({"tier": "kev"}, "find_out", "P2"),                                                  # unknowns never downgrade a KEV
    ({"tier": "kev", "deployed": "yes", "exposed": "yes", "evidence": "yes"}, "incident", "P1"),
    ({"tier": "routine", "evidence": "yes"}, "incident", "P2"),                           # evidence makes an incident at any tier
    ({"tier": "kev", "deployed": "no"}, "not_affected", "P4"),
    ({"tier": "kev", "deployed": "no", "evidence": "yes"}, "incident", "P1"),             # evidence beats "not deployed"
    ({"tier": "poc", "exposed": "yes"}, "urgent", "P2"),
    ({"tier": "poc", "exposed": "no"}, "watch", "P3"),
    ({"tier": "likely"}, "watch", "P3"),
    ({"tier": "routine"}, "routine", "P4"),
    ({}, "routine", "P4"),
])
def test_verdict(a, verdict, prio):
    out = run_js(f"ir.irVerdict({json.dumps(a)})")
    assert (out["verdict"], out["priority"]) == (verdict, prio)
    assert out["steps"] == run_js(f"ir.IR_STEPS[{json.dumps(verdict)}]") and out["steps"]


def test_no_kev_alone_is_never_incident():
    for tier in ("kev", "poc", "likely", "routine"):
        for dep in ("yes", "no", "unknown"):
            for exp in ("yes", "no", "unknown"):
                assert run_js(f"ir.irVerdict({{tier:{json.dumps(tier)},deployed:{json.dumps(dep)},exposed:{json.dumps(exp)},evidence:'no'}}).verdict") != "incident"


def _playbook(ctx):
    return run_js(f"ir.irPlaybookMd({json.dumps(ctx)})")


CTX = {"product": "Demo <b>app</b>", "variant": "ref", "version": "1.0", "date": "2026-10-15", "by": "A. Analyst",
       "rows": [{"id": "CVE-1", "label": "log4j-core@2.14.1", "tier": "kev", "def": {"kev": True, "kev_info": {"date": "2021-12-10"}, "epss": 0.99, "poc": {"n": 5}}},
                {"id": "CVE-2", "label": "evil|pipe`@1", "tier": "poc", "def": {"poc": {"n": 1}, "epss": 0.01}},
                {"id": "CVE-3", "label": "lodash@4", "tier": "routine", "def": {}}],
       "stewards": {"log4j-core": "Platform team"}, "flags": [{"label": "log4j-core@2.14.1", "reason": "defective", "note": "x\ny|z"}]}


def test_playbook_has_all_nine_sections_and_data():
    md = _playbook(CTX)
    import re
    heads = re.findall(r"^## (\d)\. ", md, flags=re.M)
    assert heads == [str(i) for i in range(1, 10)]
    assert "Platform team" in md and "NONE ASSIGNED" in md          # steward found / missing
    assert "2021-12-10" in md and "99.0%" in md and "CVE-1" in md
    assert "CVE-3" not in md.split("### Decision tree")[0].split("### Priority findings")[1]  # routine CVEs are not priority findings
    assert "KEV is not an incident" in md


def test_playbook_escapes_untrusted_sbom_text():
    md = _playbook(CTX)
    assert "<b>" not in md and "&lt;b&gt;" in md                   # html neutralised
    assert "evil\\|pipe'@1" in md                                   # pipe escaped, backtick removed
    flag_rows = [l for l in md.splitlines() if l.startswith("| log4j-core@2.14.1 | defective")]
    assert flag_rows and flag_rows[0].count(" | ") == 2 and "x y\\|z" in flag_rows[0]  # newline flattened, pipe escaped


def test_playbook_without_priority_findings():
    md = _playbook({**CTX, "rows": [CTX["rows"][2]], "stewards": {}, "flags": []})
    assert "_None._" in md and "_No packages flagged._" in md
