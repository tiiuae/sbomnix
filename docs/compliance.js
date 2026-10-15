"use strict";
/* SBOM Explorer — licence compliance, policy checks and SBOM export (CycloneDX, SPDX, VEX), attribution notice.
   Pure functions first (run under node by tests/test_compliance.py and scripts/sbom-policy.js), browser UI at the bottom.
   Classes are a triage aid, not legal advice. The Python twin of licenseClass() is license_class() in src/sbomnix/explorify.py;
   tests/resources/license_cases.json checks both. */

const LIC_TOKEN = /\(|\)|,|[^\s(),]+/g;

/* SPDX licence expression -> class ("permissive" ... "proprietary", or "unknown"). OR = licensee picks the least restrictive known
   option; AND and commas = strictest; WITH <known linking exception> softens strong copyleft. Unknown part of an AND, or a malformed
   expression, is "unknown": never reported as clean. */
function licenseClass(expr, table) {
  if (!expr || ["NOASSERTION", "NONE"].includes(String(expr).trim().toUpperCase())) return "unknown";
  const classes = Object.fromEntries(Object.entries(table.classes).map(([k, v]) => [k.toLowerCase(), v])), rank = table.rank;
  const soften = new Set((table.exceptions_soften || []).map(x => x.toLowerCase())), toks = String(expr).match(LIC_TOKEN) || [];
  let pos = 0;
  const peek = () => (pos < toks.length ? toks[pos] : null), take = () => toks[pos++], up = t => (t === null ? "" : t.toUpperCase());
  function atom() {
    const t = peek();
    if (t === null || t === ")" || t === "," || ["AND", "OR", "WITH"].includes(up(t))) throw new Error("expected licence");
    take();
    if (t === "(") { const v = orExpr(); if (peek() !== ")") throw new Error("missing )"); take(); return v; }
    const cls = classes[t.toLowerCase()];
    let v = rank.includes(cls) ? rank.indexOf(cls) : null;
    if (up(peek()) === "WITH") {
      take(); const exc = peek() !== null ? take() : "";
      if (v !== null && rank[v] === "strong-copyleft" && soften.has(exc.toLowerCase())) v = rank.indexOf("weak-copyleft");
    }
    return v;
  }
  function andExpr() {
    const vals = [atom()];
    while (peek() !== null && (up(peek()) === "AND" || peek() === ",")) { take(); vals.push(atom()); }
    return vals.some(v => v === null) ? null : Math.max(...vals);
  }
  function orExpr() {
    const vals = [andExpr()];
    while (up(peek()) === "OR") { take(); vals.push(andExpr()); }
    const known = vals.filter(v => v !== null);
    return known.length ? Math.min(...known) : null;
  }
  try { const v = orExpr(); if (pos !== toks.length) return "unknown"; return v === null ? "unknown" : rank[v]; } catch (_) { return "unknown"; }
}

/* Does the licence require attribution? true / false / null (unknown licence: cannot say). */
function attributionRequired(expr, table) {
  if (licenseClass(expr, table) === "unknown") return null;
  const free = new Set((table.no_attribution || []).map(x => x.toLowerCase())), ids = (String(expr).match(LIC_TOKEN) || []).filter(t => !["(", ")", ",", "AND", "OR", "WITH"].includes(t.toUpperCase()));
  return !ids.every(t => free.has(t.toLowerCase()));
}

const TRUSTED_CLASSES = ["permissive", "weak-copyleft", "strong-copyleft", "proprietary"];
/* component rows of a variant with their licence class. Rows built by older tools carry a class we only trust when it is specific. */
function licenseRows(v, table) {
  return v.components.map((c, i) => {
    let cls = licenseClass(c[4], table);
    if (cls === "unknown" && !c[4] && TRUSTED_CLASSES.includes(c[5])) cls = c[5];
    return {i, name: c[0], version: c[1], eco: c[2], license: c[4] || "", cls, status: c[6], key: c[7] || ""};
  });
}

/* ---------- policy ---------- */
const SEV_ORDER = ["critical", "high", "medium", "low", "unknown"];
const DEFAULT_POLICY = {denyClasses: ["strong-copyleft", "other", "proprietary"], denyLicenses: [], requireLicense: true, failSeverity: "high", blockKev: true, requireChecked: true, requireSteward: false};
const POLICY_RULES = ["licenseClass", "licenseDenied", "licenseMissing", "kev", "severity", "checked", "steward"];

/* ctx: {rows (licenseRows), v (variant), policy, stewards: {componentName: who} | null}. Returns {pass, rules: [{id, pass, skipped, offenders: [string]}]} */
function evalPolicy({rows, v, policy, stewards}) {
  const pol = {...DEFAULT_POLICY, ...(policy || {})}, last = v.history[v.history.length - 1], defs = v.vuln_defs || {};
  const pairs = (last.cve_pairs || []).map(([cve, , , label]) => ({cve, label, d: defs[cve] || {}}));
  const rules = [];
  const add = (id, offenders, skipped) => rules.push({id, pass: !offenders.length, skipped: !!skipped, offenders: [...new Set(offenders)]});
  add("licenseClass", pol.denyClasses.length ? rows.filter(r => pol.denyClasses.includes(r.cls)).map(r => `${r.name}@${r.version} (${r.cls}: ${r.license})`) : [], !pol.denyClasses.length);
  const deny = pol.denyLicenses.map(x => x.toLowerCase());
  add("licenseDenied", deny.length ? rows.filter(r => (r.license.match(LIC_TOKEN) || []).some(t => deny.includes(t.toLowerCase()))).map(r => `${r.name}@${r.version} (${r.license})`) : [], !deny.length);
  add("licenseMissing", pol.requireLicense ? rows.filter(r => r.cls === "unknown").map(r => `${r.name}@${r.version}`) : [], !pol.requireLicense);
  add("kev", pol.blockKev ? pairs.filter(p => p.d.kev).map(p => `${p.cve} in ${p.label}`) : [], !pol.blockKev);
  const limit = SEV_ORDER.indexOf(pol.failSeverity);
  add("severity", limit >= 0 && pol.failSeverity !== "off" ? pairs.filter(p => { const s = SEV_ORDER.indexOf(p.d.sev || "unknown"); return s >= 0 && s <= limit && p.d.sev !== "unknown"; }).map(p => `${p.cve} (${p.d.sev}) in ${p.label}`) : [], pol.failSeverity === "off" || limit < 0);
  add("checked", pol.requireChecked ? rows.filter(r => r.status === "pending" || r.status === "unmatched" || r.status === "none").map(r => `${r.name}@${r.version} (${r.status})`) : [], !pol.requireChecked);
  if (pol.requireSteward && stewards) {
    const hot = [...new Set(pairs.filter(p => p.d.kev || (p.d.poc && p.d.poc.n > 0)).map(p => p.label))];
    add("steward", hot.filter(l => !stewards[l.split("@")[0]]).map(l => `${l} (no steward)`));
  } else add("steward", [], true);
  return {pass: rules.every(r => r.pass), rules};
}

/* ---------- attribution notice ---------- */
function attributionNotice({product, version, date, rows}) {
  const byLic = new Map();
  rows.forEach(r => { const k = r.license || "NO LICENCE FOUND"; if (!byLic.has(k)) byLic.set(k, []); byLic.get(k).push(r); });
  const out = [`THIRD-PARTY NOTICES for ${product} ${version || ""}`.trim(), `Generated ${date} from the product's SBOM.`, "",
    "This product includes the components below. Each is distributed under the licence shown. Keep this notice with redistributions and",
    "include the full licence texts where the licence requires it (SPDX texts: https://spdx.org/licenses/<id>.html).", ""];
  [...byLic.keys()].sort().forEach(lic => {
    out.push("=".repeat(72), lic, ...(lic === "NO LICENCE FOUND" ? ["WARNING: no licence was found for these components. Find out the licence before you redistribute them."] : []), "=".repeat(72));
    byLic.get(lic).sort((a, b) => a.name.localeCompare(b.name)).forEach(r => out.push(`  ${r.name} ${r.version}`.trimEnd()));
    out.push("");
  });
  out.push("Copyright holders: not recorded in the SBOM. Add them where a licence requires the copyright line.");
  return out.join("\n");
}

/* ---------- exports ---------- */
const uuid = () => (globalThis.crypto && crypto.randomUUID ? crypto.randomUUID() : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => { const r = Math.random() * 16 | 0; return (c === "x" ? r : (r & 3 | 8)).toString(16); }));
const isoNow = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");
const cdxMethod = vec => (/^CVSS:3\.1\//.test(vec || "") ? "CVSSv31" : /^CVSS:3\.0\//.test(vec || "") ? "CVSSv3" : /^CVSS:2/.test(vec || "") || /^AV:/.test(vec || "") ? "CVSSv2" : "other");
const cdxSeverity = s => (SEV_ORDER.includes(s) ? s : "unknown");

/* triage decision (recorded from the Incident triage card) -> VEX analysis. Only a recorded human decision changes the state. */
function vexAnalysis(decision) {
  if (!decision) return {state: "in_triage"};
  if (decision.verdict === "not_affected") return {state: "not_affected", justification: "code_not_present", detail: "Component not deployed (recorded triage decision " + (decision.ts || "") + ")."};
  if (decision.verdict === "incident" || decision.verdict === "trigger") return {state: "exploitable", detail: `Recorded triage decision: ${decision.verdict} (${decision.ts || ""}).`};
  return {state: "in_triage", detail: `Recorded triage decision: ${decision.verdict} (${decision.ts || ""}).`};
}

/* ctx: {product, version, rows (licenseRows), v, decisions: {cve: decision}, withVulns (bool), table} */
function toCycloneDX({product, version, rows, v, decisions = {}, withVulns = true}) {
  const refs = new Map(), used = new Set();
  const comps = rows.map(r => {
    let ref = `${r.name}@${r.version}`; for (let n = 2; used.has(ref); n++) ref = `${r.name}@${r.version}#${n}`;
    used.add(ref); refs.set(`${r.name}@${r.version}`, refs.get(`${r.name}@${r.version}`) || ref);
    const c = {type: "library", "bom-ref": ref, name: r.name};
    if (r.version) c.version = r.version;
    if (r.key.startsWith("pkg:")) c.purl = r.key; else if (r.key.startsWith("cpe:")) c.cpe = r.key;
    if (r.license) c.licenses = r.cls !== "unknown" ? [{expression: r.license.replace(/\s*,\s*/g, " AND ")}] : [{license: {name: r.license}}];
    return c;
  });
  const doc = {bomFormat: "CycloneDX", specVersion: "1.4", serialNumber: "urn:uuid:" + uuid(), version: 1,
    metadata: {timestamp: isoNow(), tools: [{vendor: "SBOM Explorer", name: "sbom-explorer", version: "1"}], component: {type: "application", "bom-ref": "root", name: product, ...(version ? {version} : {})}},
    components: comps, dependencies: [{ref: "root", dependsOn: comps.map(c => c["bom-ref"])}]};
  if (withVulns) {
    const last = v.history[v.history.length - 1], byCve = new Map();
    (last.cve_pairs || []).forEach(([cve, , , label]) => { if (!byCve.has(cve)) byCve.set(cve, new Set()); if (refs.has(label)) byCve.get(cve).add(refs.get(label)); });
    doc.vulnerabilities = [...byCve].map(([cve, set]) => {
      const d = v.vuln_defs[cve] || {}, vul = {id: cve, source: {name: d.src === "euvd" ? "EUVD" : d.src === "nvd" ? "NVD" : "OSV"}, ratings: [], affects: [...set].map(ref => ({ref})), analysis: vexAnalysis(decisions[cve])};
      if (d.score != null || d.sev) vul.ratings.push({source: {name: d.src === "euvd" ? "EUVD" : "NVD"}, ...(d.score != null ? {score: d.score} : {}), severity: cdxSeverity(d.sev), method: cdxMethod(d.vector), ...(d.vector ? {vector: d.vector} : {})});
      if (!vul.ratings.length) delete vul.ratings;
      if (d.summary) vul.description = d.summary;
      if (d.euvd && d.euvd.id) vul.references = [{id: d.euvd.id, source: {name: "EUVD", url: "https://euvd.enisa.europa.eu/vulnerability/" + d.euvd.id}}];
      if (d.kev) vul.properties = [{name: "exploited-in-the-wild", value: "true"}, ...(d.kev_info && d.kev_info.date ? [{name: "cisa-kev-date-added", value: d.kev_info.date}] : [])];
      return vul;
    });
  }
  return doc;
}

const spdxId = (s, i) => `SPDXRef-Package-${i}-${String(s).replace(/[^0-9A-Za-z.-]/g, "-")}`.slice(0, 120);
function toSPDX({product, version, rows}) {
  const pkgs = rows.map((r, i) => {
    const p = {SPDXID: spdxId(r.name, i), name: r.name, downloadLocation: "NOASSERTION", filesAnalyzed: false, licenseConcluded: "NOASSERTION",
      licenseDeclared: r.cls !== "unknown" && r.license ? r.license.replace(/\s*,\s*/g, " AND ") : "NOASSERTION", copyrightText: "NOASSERTION"};
    if (r.version) p.versionInfo = r.version;
    if (r.key.startsWith("pkg:")) p.externalRefs = [{referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: r.key}];
    else if (r.key.startsWith("cpe:")) p.externalRefs = [{referenceCategory: "SECURITY", referenceType: "cpe23Type", referenceLocator: r.key}];
    return p;
  });
  const root = {SPDXID: "SPDXRef-RootPackage", name: product, downloadLocation: "NOASSERTION", filesAnalyzed: false, licenseConcluded: "NOASSERTION", licenseDeclared: "NOASSERTION", copyrightText: "NOASSERTION", ...(version ? {versionInfo: version} : {})};
  return {spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", name: `${product}${version ? "-" + version : ""}`,
    documentNamespace: `https://sbom-explorer.invalid/spdx/${encodeURIComponent(product)}-${uuid()}`,
    creationInfo: {created: isoNow(), creators: ["Tool: sbom-explorer-1"]}, documentDescribes: ["SPDXRef-RootPackage"],
    packages: [root, ...pkgs], relationships: pkgs.map(p => ({spdxElementId: "SPDXRef-RootPackage", relationshipType: "DEPENDS_ON", relatedSpdxElement: p.SPDXID}))};
}

/* ---------- browser UI: product tab "Compliance" (uses app.js / ciso.js globals at call time) ---------- */
const POLICY_KEY = "sbom-policy", TRIAGE_KEY = "sbom-triage";
const LIC_CLASS_PILL = {permissive: "s-low", "weak-copyleft": "s-medium", "strong-copyleft": "s-high", other: "s-high", proprietary: "s-critical", unknown: "s-unknown"};
const readJson = (k, d) => { try { return JSON.parse(localStorage.getItem(k) || "null") || d; } catch (_) { return d; } };
const writeJson = (k, o) => { try { localStorage.setItem(k, JSON.stringify(o)); } catch (_) { /* storage blocked: lasts until reload */ } };
const loadPolicy = () => ({...DEFAULT_POLICY, ...readJson(POLICY_KEY, {})});
/* licenses.json is fetched once at load; the tab waits for it */
let LIC_TABLE = null;
const licensesReady = typeof fetch === "function" && typeof window !== "undefined" ? fetch("data/licenses.json").then(r => r.json()).then(j => { LIC_TABLE = j; }).catch(() => {}) : Promise.resolve();
/* triage decisions recorded from the Incident triage card, used for the VEX analysis in the CycloneDX export */
const decisionsOf = pid => { const all = readJson(TRIAGE_KEY, {}), out = {}; Object.entries(all).forEach(([k, d]) => { if (k.startsWith(pid + "|")) out[k.slice(pid.length + 1)] = d; }); return out; };
function recordDecision(pid, cve, d) { const all = readJson(TRIAGE_KEY, {}); all[pid + "|" + cve] = {...d, ts: new Date().toISOString().slice(0, 10)}; writeJson(TRIAGE_KEY, all); }
const stewardsOf = pid => { const out = {}, rv = typeof review !== "undefined" ? review.stewards : {}; Object.entries(rv).forEach(([k, who]) => { if (k.startsWith(pid + "|")) out[k.slice(pid.length + 1)] = who; }); return out; };

function complianceTab() {
  return `<p class="muted">${esc(t("cmp2.lead"))}</p><div id="compBody"><p class="muted">${esc(t("set.testing"))}</p></div>`;
}
async function wireCompliance(v) {
  await licensesReady;
  const body = document.getElementById("compBody"); if (!body) return;
  if (!LIC_TABLE) { body.innerHTML = `<p class="no">${esc(t("cmp2.nolic"))}</p>`; return; }
  const {pid, vid, p} = CUR, rows = licenseRows(v, LIC_TABLE), last = v.history[v.history.length - 1], pol = loadPolicy();
  const draw = () => {
    const pl = loadPolicy(), res = evalPolicy({rows, v, policy: pl, stewards: stewardsOf(pid)}), failN = res.rules.filter(r => !r.pass).length, dec = decisionsOf(pid);
    const classes = ["permissive", "weak-copyleft", "strong-copyleft", "other", "proprietary", "unknown"], cnt = Object.fromEntries(classes.map(k => [k, rows.filter(r => r.cls === k).length]));
    const byLic = new Map(); rows.forEach(r => { const k = r.license || ""; if (!byLic.has(k)) byLic.set(k, {license: k, cls: r.cls, names: []}); byLic.get(k).names.push(`${r.name} ${r.version}`.trim()); });
    const lics = [...byLic.values()].sort((a, b) => classes.indexOf(b.cls) - classes.indexOf(a.cls) || b.names.length - a.names.length);
    const chk = (key, label) => `<label class="small" style="display:block"><input type="checkbox" data-pol="${key}" ${pl[key] ? "checked" : ""}> ${esc(label)}</label>`;
    const denyBox = c => `<label class="small" style="display:inline-block;margin-right:12px"><input type="checkbox" data-deny="${c}" ${pl.denyClasses.includes(c) ? "checked" : ""}> ${esc(t("lic." + c))}</label>`;
    body.innerHTML = `
    <div class="card ${res.pass ? "" : "warn"}" style="margin-bottom:14px"><div class="row" style="justify-content:space-between"><h3 style="margin:0">${res.pass ? "✅" : "🚫"} ${esc(t(res.pass ? "pol.pass" : "pol.fail", {n: failN}))}</h3><span class="small muted">${esc(t("pol.also_ci"))}</span></div>
      <div class="tablewrap"><table><tbody>${res.rules.map(r => `<tr><td>${r.skipped ? "—" : r.pass ? '<b class="ok">✓</b>' : '<b class="no">✗</b>'}</td><td>${esc(t("pol.rule." + r.id))}</td><td class="small ${r.pass ? "muted" : "no"}">${r.skipped ? esc(t("pol.skipped")) : r.pass ? esc(t("pol.ok")) : `<details><summary>${esc(t("pol.offenders", {n: r.offenders.length}))}</summary>${r.offenders.slice(0, 25).map(o => `<div><code>${esc(o)}</code></div>`).join("")}${r.offenders.length > 25 ? `<div>… ${r.offenders.length - 25}</div>` : ""}</details>`}</td></tr>`).join("")}</tbody></table></div>
      <details style="margin-top:8px"><summary>${esc(t("pol.edit"))}</summary><div class="grid" style="margin-top:8px">
        <div><b class="small">${esc(t("pol.deny_classes"))}</b><div>${["weak-copyleft", "strong-copyleft", "other", "proprietary"].map(denyBox).join("")}</div>
          <label class="blk small">${esc(t("pol.deny_licenses"))}<input id="polDeny" value="${esc(pl.denyLicenses.join(", "))}" placeholder="AGPL-3.0-only, SSPL-1.0"></label></div>
        <div>${chk("requireLicense", t("pol.rule.licenseMissing"))}${chk("blockKev", t("pol.rule.kev"))}${chk("requireChecked", t("pol.rule.checked"))}${chk("requireSteward", t("pol.rule.steward"))}
          <label class="blk small">${esc(t("pol.sev"))}<select id="polSev">${["off", "critical", "high", "medium", "low"].map(k => `<option value="${k}" ${pl.failSeverity === k ? "selected" : ""}>${esc(k === "off" ? t("pol.sev_off") : t("pol.sev_at", {s: k}))}</option>`).join("")}</select></label>
          <button id="polReset" class="linkish">${esc(t("set.reset"))}</button></div></div></details></div>
    <h3>${esc(t("cmp2.licenses"))}</h3>
    <div class="kpis">${classes.filter(k => cnt[k]).map(k => `<div class="kpi"><span class="pill ${LIC_CLASS_PILL[k]}">${esc(t("lic." + k))}</span><b>${cnt[k]}</b></div>`).join("")}</div>
    <div class="tablewrap"><table><thead><tr><th>${esc(t("comp.licence"))}</th><th>${esc(t("cmp2.class"))}</th><th>${esc(t("cmp2.components"))}</th></tr></thead><tbody>${lics.slice(0, 200).map(l => `<tr><td>${l.license ? `<code>${esc(l.license)}</code>` : `<span class="no">${esc(t("cmp2.nolicence"))}</span>`}</td><td><span class="pill ${LIC_CLASS_PILL[l.cls]}">${esc(t("lic." + l.cls))}</span></td><td class="small">${l.names.length} · ${esc(l.names.slice(0, 4).join(", "))}${l.names.length > 4 ? " …" : ""}</td></tr>`).join("")}</tbody></table></div>
    <h3>${esc(t("cmp2.obligations"))}</h3><div class="grid">${classes.filter(k => cnt[k]).map(k => `<div class="card"><span class="pill ${LIC_CLASS_PILL[k]}">${esc(t("lic." + k))}</span><p class="small" style="margin:8px 0 0">${esc(LIC_TABLE.obligations[k][LANG] || LIC_TABLE.obligations[k].en)}</p></div>`).join("")}</div>
    <p class="small muted">${esc(t("cmp2.legal"))}</p>
    <h3>${esc(t("cmp2.export"))}</h3>
    <div class="row"><button class="primary" id="exCdx">CycloneDX + VEX (.json)</button><button id="exCdxLite">CycloneDX ${esc(t("cmp2.components_only"))}</button><button id="exSpdx">SPDX 2.3 (.json)</button><button id="exNotice">${esc(t("cmp2.notice"))}</button></div>
    <p class="small muted">${esc(t("cmp2.vex_note", {n: Object.keys(dec).length}))}</p>`;
    const val = k => (body.querySelector(k) || {}).value;
    body.querySelectorAll("[data-deny]").forEach(i => i.onchange = () => { const cur = loadPolicy().denyClasses.filter(x => x !== i.dataset.deny); if (i.checked) cur.push(i.dataset.deny); writeJson(POLICY_KEY, {...loadPolicy(), denyClasses: cur}); draw(); });
    body.querySelectorAll("[data-pol]").forEach(i => i.onchange = () => { writeJson(POLICY_KEY, {...loadPolicy(), [i.dataset.pol]: i.checked}); draw(); });
    body.querySelector("#polSev").onchange = () => { writeJson(POLICY_KEY, {...loadPolicy(), failSeverity: val("#polSev")}); draw(); };
    body.querySelector("#polDeny").onchange = () => { writeJson(POLICY_KEY, {...loadPolicy(), denyLicenses: val("#polDeny").split(",").map(x => x.trim()).filter(Boolean)}); draw(); };
    body.querySelector("#polReset").onclick = () => { try { localStorage.removeItem(POLICY_KEY); } catch (_) {} draw(); };
    const base = `${pid}-${vid}`, ctx = () => ({product: p.name, version: last.version, rows, v, decisions: decisionsOf(pid)});
    body.querySelector("#exCdx").onclick = () => downloadBlob(`${base}.cdx.json`, JSON.stringify(toCycloneDX(ctx()), null, 2), "application/json");
    body.querySelector("#exCdxLite").onclick = () => downloadBlob(`${base}.components.cdx.json`, JSON.stringify(toCycloneDX({...ctx(), withVulns: false}), null, 2), "application/json");
    body.querySelector("#exSpdx").onclick = () => downloadBlob(`${base}.spdx.json`, JSON.stringify(toSPDX(ctx()), null, 2), "application/json");
    body.querySelector("#exNotice").onclick = () => downloadBlob(`${base}.NOTICE.txt`, attributionNotice({product: p.name, version: last.version, date: new Date().toISOString().slice(0, 10), rows}), "text/plain");
  };
  draw();
}

if (typeof module !== "undefined" && module.exports) module.exports = {licenseClass, attributionRequired, licenseRows, evalPolicy, attributionNotice, toCycloneDX, toSPDX, vexAnalysis, DEFAULT_POLICY, POLICY_RULES};
