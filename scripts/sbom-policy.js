#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Policy gate for SBOM Explorer product files: the same rules as the Compliance tab (docs/compliance.js), for CI.
//
//   node scripts/sbom-policy.js docs/data/my-product.json [--variant nix] [--policy policy.json] [--licenses docs/data/licenses.json]
//
// policy.json overrides the defaults, e.g. {"denyClasses": ["strong-copyleft"], "failSeverity": "critical", "blockKev": true}.
// Exit code: 0 all rules pass, 1 a rule fails, 2 bad usage or unreadable input.
// The steward rule needs data kept in the browser, so it is reported as "not evaluated" here.
"use strict";
const fs = require("fs"), path = require("path");
const c = require(path.join(__dirname, "..", "docs", "compliance.js"));

function fail(msg) { console.error("sbom-policy: " + msg); process.exit(2); }
const args = process.argv.slice(2), opt = {};
for (let i = 0; i < args.length; i++) if (args[i].startsWith("--")) { if (i + 1 >= args.length) fail(`${args[i]} needs a value`); opt[args[i].slice(2)] = args[++i]; }
const positional = args.filter((a, i) => !a.startsWith("--") && !(i > 0 && args[i - 1].startsWith("--")));
if (positional.length !== 1) fail("usage: node scripts/sbom-policy.js <product.json> [--variant id] [--policy file] [--licenses file]");
const read = (f, what) => { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch (e) { fail(`cannot read ${what} ${f}: ${e.message}`); } };
const product = read(positional[0], "product"), table = read(opt.licenses || path.join(__dirname, "..", "docs", "data", "licenses.json"), "licence table");
if (product.bomFormat) fail("this is a raw SBOM; add it to the Explorer first (sbomnix --explorer-dir, then scripts/cve-check.py --explorer-product) and pass the product JSON");
if (!product.variants) fail("not an Explorer product file (no variants)");
const vid = opt.variant || Object.keys(product.variants)[0], v = product.variants[vid];
if (!v) fail(`no variant ${vid}; available: ${Object.keys(product.variants).join(", ")}`);
const policy = opt.policy ? read(opt.policy, "policy") : {};
const res = c.evalPolicy({rows: c.licenseRows(v, table), v, policy, stewards: null});
console.log(`${product.name} / ${vid}: ${res.pass ? "PASS" : "FAIL"}`);
for (const r of res.rules) {
  console.log(`  ${r.skipped ? "SKIP" : r.pass ? "PASS" : "FAIL"}  ${r.id}${r.offenders.length ? ` (${r.offenders.length})` : ""}`);
  r.offenders.slice(0, 10).forEach(o => console.log(`        ${o}`));
  if (r.offenders.length > 10) console.log(`        ... ${r.offenders.length - 10} more`);
}
process.exit(res.pass ? 0 : 1);
