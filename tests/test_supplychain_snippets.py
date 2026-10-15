# SPDX-License-Identifier: Apache-2.0
"""docs/supplychain.js and docs/snippets.js under node."""
import json
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
TABLE = json.loads((ROOT / "docs/data/licenses.json").read_text())
PRODUCT = json.loads((ROOT / "docs/data/cve-reference-app.json").read_text())["variants"]["reference"]


def js(module, expr, **data):
    code = (f"const m=require({json.dumps(str(ROOT / 'docs' / module))});const D=JSON.parse(require('fs').readFileSync(0,'utf8'));"
            f"const {{{','.join(data)}}}=D;process.stdout.write(JSON.stringify({expr}))") if data else (
        f"const m=require({json.dumps(str(ROOT / 'docs' / module))});process.stdout.write(JSON.stringify({expr}))")
    return json.loads(subprocess.run(["node", "-e", code], input=json.dumps(data), capture_output=True, text=True, check=True).stdout)


# ---------------------------------------------------------------- supply chain
def tiers(n, edges):
    return js("supplychain.js", "m.scTiers(n,g)", n=n, g={"root": "p", "edges": edges})


def test_flat_when_no_edges():
    r = tiers(3, [])
    assert r["hasEdges"] is False and r["tiers"] == [[0, 1, 2]] and r["unlinked"] == []


def test_multi_tier_depths():
    r = tiers(5, [[-1, 0], [-1, 1], [0, 2], [2, 3], [1, 3]])        # 3 is reachable at depth 3 via 0->2->3 and depth 2 via 1->3
    assert r["tiers"] == [[0, 1], [2, 3], []] or r["tiers"] == [[0, 1], [2, 3]]   # shortest path wins: 3 sits in tier 2
    assert r["unlinked"] == [4] and r["hasEdges"] is True


def test_cycles_do_not_loop_forever_and_unlinked_are_listed():
    r = tiers(4, [[-1, 0], [0, 1], [1, 0], [2, 3], [3, 2]])         # 2<->3 is a cycle nobody reaches
    assert r["tiers"][0] == [0] and r["tiers"][1] == [1] and sorted(r["unlinked"]) == [2, 3]


def test_out_of_range_edges_are_ignored():
    r = tiers(2, [[-1, 0], [0, 99], [-1, -1]])
    assert r["tiers"] == [[0]] and r["unlinked"] == [1]


def rows_for(v):
    return [{"name": c[0], "version": c[1], "status": c[6], "supplier": (c + [""] * 9)[8]} for c in v["components"]]


def test_facts_on_real_product():
    facts = js("supplychain.js", "m.scFacts(v,r)", v=PRODUCT, r=rows_for(PRODUCT))
    by = {c[0]: f for c, f in zip(PRODUCT["components"], facts)}
    assert by["log4j-core"]["kev"] is True and by["log4j-core"]["state"] == "kev" and by["log4j-core"]["worst"] == "critical"
    assert by["lodash"]["state"] in ("high", "medium", "critical", "low")           # has CVEs, not KEV
    assert all(f["cves"] > 0 for f in facts)


def test_unchecked_is_not_clean():
    v = {"components": [["a", "1", "x", "L", "", "u", "pending", "", ""]], "vuln_defs": {}, "history": [{"cve_pairs": []}]}
    assert js("supplychain.js", "m.scFacts(v,r)", v=v, r=rows_for(v))[0]["state"] == "unchecked"
    v["components"][0][6] = "nvd"
    assert js("supplychain.js", "m.scFacts(v,r)", v=v, r=rows_for(v))[0]["state"] == "clean"


def test_suppliers_group_and_depend_on():
    rows = [{"supplier": "ACME"}, {"supplier": "ACME"}, {"supplier": "Globex"}, {"supplier": ""}]
    facts = [{"kev": True, "worst": "high"}, {"kev": False, "worst": "low"}, {"kev": False, "worst": ""}, {"kev": False, "worst": ""}]
    out = js("supplychain.js", "m.scSuppliers(r,f,g).map(s=>({...s,dependsOn:[...s.dependsOn]}))", r=rows, f=facts, g={"edges": [[-1, 0], [0, 2], [1, 2], [2, 3], [0, 1]]})
    names = [s["name"] for s in out]
    assert names == ["ACME", "Globex", ""]                                          # no-supplier group is last, never dropped
    acme = out[0]
    assert len(acme["idx"]) == 2 and acme["kev"] == 1 and acme["worst"] == "high"
    assert dict(acme["dependsOn"]) == {"Globex": 2}                                  # same-supplier edge 0->1 is not a dependency on another supplier


# ---------------------------------------------------------------- snippets
def analyse(text, policy=None):
    return js("snippets.js", "m.snAnalyze({name:'f.c',text:T,table:t,policy:p})", T=text, t=TABLE, p=policy)


LGPL_HEADER = """/*
 * Copyright (c) 2020 Example Corp
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the
 * GNU Lesser General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
int main(void) { return 0; }
"""


def test_spdx_tag_detected_with_copyright():
    r = analyse("// SPDX-FileCopyrightText: 2024 Jane Doe\n// SPDX-License-Identifier: MIT\nint x;\n")
    assert r["expr"] == "MIT" and r["cls"] == "permissive" and r["status"] == "compliant" and r["attribution"] is True
    assert r["findings"][0]["how"] == "spdx-tag" and r["findings"][0]["line"] == 2 and r["copyrights"] == ["2024 Jane Doe"]


def test_lgpl_header_is_weak_copyleft_and_allowed_by_default():
    r = analyse(LGPL_HEADER)
    assert r["expr"] == "LGPL-2.1-or-later" and r["cls"] == "weak-copyleft" and r["status"] == "compliant"
    assert r["attribution"] is True and "LGPL" in r["families"] and r["copyrights"][0].startswith("2020 Example Corp")


def test_gpl_is_noncompliant_by_default_policy():
    r = analyse("/* SPDX-License-Identifier: GPL-3.0-only */\n")
    assert r["cls"] == "strong-copyleft" and r["status"] == "noncompliant"
    assert analyse("/* SPDX-License-Identifier: GPL-3.0-only */\n", {"denyClasses": []})["status"] == "compliant"


def test_denied_licence_id_beats_allowed_class():
    assert analyse("// SPDX-License-Identifier: MIT\n", {"denyLicenses": ["mit"]})["status"] == "noncompliant"


def test_no_notice_is_unknown_not_compliant():
    r = analyse("int main(void) { return 0; }\n")
    assert r["status"] == "unknown" and r["expr"] == "" and r["attribution"] is None and r["cls"] == "unknown"


def test_unversioned_gnu_header_needs_review():
    r = analyse("/* This program is free software under the GNU Lesser General Public License. */\n")
    assert r["expr"].startswith("LGPL") and r["cls"] == "weak-copyleft" and r["status"] == "review"      # low confidence: never "compliant"


def test_tag_and_header_disagree_is_flagged():
    r = analyse("// SPDX-License-Identifier: MIT\n/* Licensed under the Apache License, Version 2.0 */\n")
    assert r["conflict"] is True and r["status"] == "review"


def test_apache_bsd_mpl_unlicense_headers():
    assert analyse("/* Licensed under the Apache License, Version 2.0 (the \"License\") */")["expr"] == "Apache-2.0"
    assert analyse("Redistribution and use in source and binary forms, with or without modification, are permitted. Neither the name of X")["expr"] == "BSD-3-Clause"
    assert analyse("This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.")["expr"] == "MPL-2.0"
    r = analyse("This is free and unencumbered software released into the public domain.")
    assert r["expr"] == "Unlicense" and r["attribution"] is False


def test_only_the_top_of_a_file_is_read():
    text = "\n" * 450 + "// SPDX-License-Identifier: MIT\n"
    assert analyse(text)["status"] == "unknown"


def test_notice_groups_and_warns():
    results = [analyse("// SPDX-License-Identifier: MIT\n"), analyse("int x;"), analyse("// SPDX-License-Identifier: CC0-1.0\n")]
    for i, r in enumerate(results):
        r["name"] = f"f{i}.c"
    text = js("snippets.js", "m.snNotice(r,{product:'P',date:'2026-01-01'})", r=results)
    assert "THIRD-PARTY CODE NOTICES for P" in text and "f0.c" in text and "NO LICENCE FOUND" in text and "f1.c" in text
    assert "f2.c" not in text                                                          # CC0 needs no attribution


def test_attribution_required_function():
    c = lambda e: js("compliance.js", "m.attributionRequired(e,t)", e=e, t=TABLE)
    assert c("MIT") is True and c("CC0-1.0") is False and c("MIT AND CC0-1.0") is True and c("Made-Up-1.0") is None and c("") is None
