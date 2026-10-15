# SPDX-License-Identifier: Apache-2.0
"""Every translation key used by the IR code (docs/ir.js) exists in both languages, dynamic keys included."""
import json
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

JS = r"""
const fs = require('fs'), vm = require('vm');
const src = fs.readFileSync(process.argv[1] + '/docs/i18n.js', 'utf8') + '\n;this.__I18N = I18N;';
const ctx = {navigator: {language: 'en'}, localStorage: {getItem: () => null, setItem() {}}, document: {documentElement: {}}, location: {hash: ''}, window: {}};
vm.createContext(ctx); vm.runInContext(src, ctx);
const ir = require(process.argv[1] + '/docs/ir.js');
const dyn = [];
ir.IR_TIERS.forEach(k => { dyn.push('ir.tier.' + k, 'ir.tier.' + k + '_d'); });
Object.entries(ir.IR_STEPS).forEach(([v, steps]) => { dyn.push('ir.v.' + v, 'ir.v.' + v + '_d'); steps.forEach(s => dyn.push('ir.step.' + s)); });
['deployed', 'exposed', 'evidence', 'cve'].forEach(q => dyn.push('ir.q.' + q));
['unknown', 'yes', 'no'].forEach(a => dyn.push('ir.a.' + a));
const have = lang => Object.keys(ctx.__I18N[lang]);
process.stdout.write(JSON.stringify({dyn, en: have('en'), pl: have('pl')}));
"""


def test_all_ir_keys_translated():
    out = json.loads(subprocess.run(["node", "-e", JS, str(ROOT)], capture_output=True, text=True, check=True).stdout)
    # static keys only: a trailing "." is the prefix of a dynamically built key, checked via `dyn`
    static = {k for f in ("ir.js", "compliance.js", "supplychain.js", "snippets.js", "library.js") for k in re.findall(r'\bt\("((?:ir|tab|cmp2|pol|lic|sc|sn|lib)\.[A-Za-z_.0-9]+)"', (ROOT / "docs" / f).read_text()) if not k.endswith(".")}
    dynamic = {"lic." + c for c in ("permissive", "weak-copyleft", "strong-copyleft", "other", "proprietary", "unknown")} | {"pol.rule." + r for r in ("licenseClass", "licenseDenied", "licenseMissing", "kev", "severity", "checked", "steward")} | {"tab.compliance", "tab.supplychain", "nav.library"} | {"lib.step." + k for k in ("osv", "details", "kev", "epss", "poc")} | {"sc.state." + k for k in ("kev", "critical", "high", "medium", "low", "unknown", "clean", "unchecked")} | {"sn.status." + k for k in ("compliant", "review", "noncompliant", "unknown")} | {"sn.why." + k for k in ("compliant", "review", "noncompliant", "unknown")} | {"sn.conf." + k for k in ("high", "medium", "low")}
    needed = static | dynamic | set(out["dyn"]) | {"tab.ir"}
    missing_en = sorted(k for k in needed if k not in out["en"])
    missing_pl = sorted(k for k in needed if k not in out["pl"])
    assert not missing_en and not missing_pl, (missing_en, missing_pl)
    assert len(needed) > 200  # the check really looked at the whole feature
