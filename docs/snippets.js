"use strict";
/* SBOM Explorer — licence detection in source code ("snippets"): SPDX tags and well-known licence headers, obligations,
   compliance status against the policy, and an attribution notice. Pure functions first (node-exportable), browser page below.
   Detection is pattern matching on the top of a file. It finds what a file says about itself, not what is legally true: a file
   with no notice is "unknown" (no licence means no right to use it), and low-confidence matches are marked for review. */

if (typeof module !== "undefined" && typeof licenseClass === "undefined") Object.assign(globalThis, require("./compliance.js"));  // node: the browser has these as globals

const SN_HEAD_LINES = 400, SN_MAX_FILES = 50, SN_MAX_BYTES = 200000;

/* version of a GNU licence mentioned in the text: "2.1-or-later", "3.0-only", or "" when it does not say */
function snGnuVersion(text, base) {
  const m = text.match(/version\s+(2\.1|3|2)\b/i) || text.match(/\b(?:v|version)?\s*(2\.1|3(?:\.0)?|2(?:\.0)?)\s+of\s+the\s+License/i);
  if (!m) return "";
  const v = m[1] === "3" ? "3.0" : m[1] === "2" && base !== "LGPL" ? "2.0" : m[1], later = /any later version|or \(at your option\) any later/i.test(text);
  return `${v}-${later ? "or-later" : "only"}`;
}

const SN_HEADERS = [
  {re: /GNU\s+(?:Lesser|Library)\s+General\s+Public\s+License/i, id: t => { const v = snGnuVersion(t, "LGPL"); return v ? {id: "LGPL-" + v, conf: "high"} : {id: "LGPL (version not stated)", conf: "low"}; }},
  {re: /GNU\s+Affero\s+General\s+Public\s+License/i, id: t => { const v = snGnuVersion(t, "AGPL"); return v ? {id: "AGPL-" + v, conf: "high"} : {id: "AGPL (version not stated)", conf: "low"}; }},
  {re: /GNU\s+General\s+Public\s+License/i, skip: /Lesser|Library|Affero/i, id: t => { const v = snGnuVersion(t, "GPL"); return v ? {id: "GPL-" + v, conf: "high"} : {id: "GPL (version not stated)", conf: "low"}; }},
  {re: /Apache License,?\s*(?:Version|v\.?)\s*2\.0|apache\.org\/licenses\/LICENSE-2\.0/i, id: () => ({id: "Apache-2.0", conf: "high"})},
  {re: /Mozilla Public License,?\s*(?:Version|v\.?)\s*2\.0|mozilla\.org\/MPL\/2\.0/i, id: () => ({id: "MPL-2.0", conf: "high"})},
  {re: /Eclipse Public License\s*[-,]?\s*(?:v|Version)\.?\s*2\.0/i, id: () => ({id: "EPL-2.0", conf: "high"})},
  {re: /Eclipse Public License\s*[-,]?\s*(?:v|Version)\.?\s*1\.0/i, id: () => ({id: "EPL-1.0", conf: "high"})},
  {re: /Permission is hereby granted, free of charge, to any person obtaining a copy/i, id: () => ({id: "MIT", conf: "medium"})},
  {re: /Permission to use, copy, modify, and\/or distribute this software for any purpose with or without fee/i, id: () => ({id: "ISC", conf: "high"})},
  {re: /Redistribution and use in source and binary forms, with or without\s+modification/i, id: t => ({id: /Neither the name of/i.test(t) ? "BSD-3-Clause" : "BSD-2-Clause", conf: "medium"})},
  {re: /This is free and unencumbered software released into the public domain/i, id: () => ({id: "Unlicense", conf: "high"})},
  {re: /Proprietary and confidential|Unauthorized copying of this file/i, id: () => ({id: "LicenseRef-proprietary", conf: "medium"})}];

/* what a file says about its own licence: [{id, how: "spdx-tag"|"header", line, conf, text}] and copyright lines */
function snDetect(text) {
  const src = String(text || ""), lines = src.split(/\r?\n/).slice(0, SN_HEAD_LINES), head = lines.join("\n"), findings = [], copyrights = [];
  lines.forEach((ln, i) => {
    const tag = ln.match(/SPDX-License-Identifier:\s*(.+?)\s*(?:\*\/|-->|#\}|$)/);
    if (tag && tag[1].trim()) findings.push({id: tag[1].trim().replace(/\s*\*+$/, ""), how: "spdx-tag", line: i + 1, conf: "high", text: ln.trim().slice(0, 120)});
    const cr = ln.match(/(?:SPDX-FileCopyrightText:|Copyright\s*(?:\(c\)|©)?)\s*(.{3,120})/i);
    if (cr && copyrights.length < 5 && !/SPDX-License-Identifier/.test(ln)) copyrights.push(cr[1].replace(/\s*(\*\/|-->)\s*$/, "").trim());
  });
  SN_HEADERS.forEach(h => {
    const m = head.match(h.re);
    if (!m || (h.skip && h.skip.test(m[0]))) return;
    const near = head.slice(Math.max(0, m.index - 200), m.index + 600), r = h.id(near);
    findings.push({id: r.id, how: "header", line: head.slice(0, m.index).split("\n").length, conf: r.conf, text: m[0].replace(/\s+/g, " ").slice(0, 120)});
  });
  return {findings, copyrights};
}

/* licence class, with a family fallback for ids that name a licence without its version ("LGPL (version not stated)") */
function snClass(expr, table) {
  const c = licenseClass(expr, table);
  if (c !== "unknown") return c;
  const fam = String(expr || "").trim();
  return /^LGPL/i.test(fam) || /^MPL/i.test(fam) ? "weak-copyleft" : /^A?GPL/i.test(fam) ? "strong-copyleft" : "unknown";
}
const snFamily = id => (/^LGPL/i.test(id) ? "LGPL" : /^AGPL/i.test(id) ? "AGPL" : /^GPL/i.test(id) ? "GPL" : /^MPL/i.test(id) ? "MPL" : /^Apache/i.test(id) ? "Apache" : /^EPL/i.test(id) ? "EPL" : /^BSD/i.test(id) ? "BSD" : /^MIT/i.test(id) ? "MIT" : /^ISC/i.test(id) ? "ISC" : "");

/* One file: what it declares, class, attribution duty, obligations and the status against the policy.
   status: compliant | review | noncompliant | unknown. "compliant" means "allowed by YOUR policy", not a legal opinion. */
function snAnalyze({name, text, table, policy}) {
  const det = snDetect(text), tags = det.findings.filter(f => f.how === "spdx-tag"), heads = det.findings.filter(f => f.how === "header");
  const chosen = tags.length ? tags : heads, ids = [...new Set(chosen.map(f => f.id))], expr = ids.join(" AND ");
  const headIds = new Set(heads.map(f => f.id.split("-")[0])), tagIds = new Set(tags.map(f => f.id.split("-")[0]));
  const conflict = tags.length > 0 && heads.length > 0 && [...headIds].some(h => !tagIds.has(h));
  const cls = ids.length ? snClass(expr, table) : "unknown", pol = {denyClasses: ["strong-copyleft", "other", "proprietary"], denyLicenses: [], ...(policy || {})};
  const deny = pol.denyLicenses.map(x => x.toLowerCase());
  const lowOnly = chosen.length > 0 && chosen.every(f => f.conf === "low");
  let status;
  if (!ids.length) status = "unknown";
  else if (pol.denyClasses.includes(cls) || ids.some(i => deny.includes(i.toLowerCase()))) status = "noncompliant";
  else if (cls === "unknown" || conflict || lowOnly) status = "review";
  else status = "compliant";
  const notes = [...new Set(ids.map(snFamily).filter(Boolean))].map(f => f);
  return {name, findings: det.findings, copyrights: det.copyrights, expr, cls, attribution: ids.length ? attributionRequired(expr, table) : null, status, conflict, families: notes};
}

/* attribution notice for the analysed files: grouped by licence, with the copyright lines found; unknown files are called out */
function snNotice(results, {product = "this project", date = ""} = {}) {
  const groups = new Map();
  results.forEach(r => { const k = r.expr || "NO LICENCE FOUND"; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(r); });
  const out = [`THIRD-PARTY CODE NOTICES for ${product}`, date ? `Generated ${date} from licence notices found in source files.` : "", "",
    "Each file below carries the licence shown. Keep these notices with redistributions and include the full licence texts where required",
    "(SPDX texts: https://spdx.org/licenses/<id>.html). Detection is based on the notices inside the files; verify before relying on it.", ""];
  [...groups.keys()].sort().forEach(k => {
    const files = groups.get(k).filter(r => r.attribution !== false || k === "NO LICENCE FOUND");
    if (!files.length) return;
    out.push("=".repeat(72), k, ...(k === "NO LICENCE FOUND" ? ["WARNING: these files declare no licence. Without a licence you have no right to use or redistribute them."] : []), "=".repeat(72));
    files.sort((a, b) => a.name.localeCompare(b.name)).forEach(r => out.push(`  ${r.name}${r.copyrights.length ? "  (" + r.copyrights.join("; ") + ")" : ""}`));
    out.push("");
  });
  return out.join("\n");
}

/* ---------- browser page: #/snippet ---------- */
const SN_STATUS_PILL = {compliant: "s-low", review: "s-medium", noncompliant: "s-critical", unknown: "s-unknown"};
const SN_CLS_PILL = {permissive: "s-low", "weak-copyleft": "s-medium", "strong-copyleft": "s-high", other: "s-high", proprietary: "s-critical", unknown: "s-unknown"};

function snippetView() {
  $crumb.textContent = t("sn.title");
  $app.innerHTML = `<h2>🧩 ${esc(t("sn.title"))}</h2><p class="muted">${esc(t("sn.lead"))}</p>
    <div class="card"><div id="snDrop" class="drop" tabindex="0" role="button" aria-label="${esc(t("sn.drop"))}">${esc(t("sn.drop"))}<input type="file" id="snFile" multiple hidden></div>
    <label class="blk" style="margin-top:10px">${esc(t("sn.paste"))}<textarea id="snText" rows="6" spellcheck="false" style="width:100%;font-family:monospace" placeholder="// SPDX-License-Identifier: LGPL-2.1-or-later"></textarea></label>
    <div class="row"><button class="primary" id="snGo">${esc(t("sn.go"))}</button><a href="#/check" class="btn">${esc(t("nav.check"))}</a><span id="snMsg" class="small"></span></div>
    <p class="small muted">${esc(t("sn.privacy"))}</p></div><div id="snOut" style="margin-top:14px"></div>`;
  const files = [], msg = (ok, x) => { const m = document.getElementById("snMsg"); m.className = "small " + (ok ? "ok" : "no"); m.textContent = x; };
  const drop = document.getElementById("snDrop"), input = document.getElementById("snFile");
  const addFiles = list => {
    const picked = [...list].slice(0, SN_MAX_FILES);
    Promise.all(picked.map(f => f.slice(0, SN_MAX_BYTES).text().then(text => ({name: f.name.slice(0, 120), text})))).then(rs => { files.splice(0, files.length, ...rs); msg(true, t("sn.loaded", {n: rs.length})); analyse(); });
  };
  drop.onclick = () => input.click(); drop.onkeydown = e => { if (e.key === "Enter" || e.key === " ") input.click(); };
  input.onchange = () => input.files.length && addFiles(input.files);
  ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => e.dataTransfer.files.length && addFiles(e.dataTransfer.files));
  document.getElementById("snGo").onclick = () => { const txt = document.getElementById("snText").value; if (txt.trim()) files.splice(0, files.length, {name: t("sn.pasted"), text: txt}); analyse(); };
  async function analyse() {
    if (typeof licensesReady !== "undefined") await licensesReady;
    const out = document.getElementById("snOut");
    if (!files.length) { msg(false, t("sn.nothing")); out.innerHTML = ""; return; }
    if (typeof LIC_TABLE === "undefined" || !LIC_TABLE) { msg(false, t("cmp2.nolic")); return; }
    const pol = typeof loadPolicy === "function" ? loadPolicy() : {}, res = files.map(f => snAnalyze({name: f.name, text: f.text, table: LIC_TABLE, policy: pol}));
    const count = k => res.filter(r => r.status === k).length, date = new Date().toISOString().slice(0, 10);
    msg(true, t("sn.done", {n: res.length}));
    const yn = a => (a === null ? t("sn.unknown") : a ? t("ir.a.yes") : t("ir.a.no"));
    const card = r => `<div class="card"><div class="row" style="justify-content:space-between"><b>${esc(r.name)}</b><span class="pill ${SN_STATUS_PILL[r.status]}">${esc(t("sn.status." + r.status))}</span></div>
      <div class="kpis" style="margin:10px 0"><div class="kpi"><span class="muted small">${esc(t("sn.license_type"))}</span><b style="font-size:1.1rem">${r.expr ? esc(r.expr) : "—"}</b><span class="pill ${SN_CLS_PILL[r.cls]}">${esc(t("lic." + r.cls))}</span></div>
        <div class="kpi"><span class="muted small">${esc(t("sn.attribution"))}</span><b>${esc(yn(r.attribution))}</b></div><div class="kpi"><span class="muted small">${esc(t("sn.status"))}</span><b style="font-size:1.1rem">${esc(t("sn.status." + r.status))}</b></div></div>
      ${r.conflict ? `<p class="small no">${esc(t("sn.conflict"))}</p>` : ""}<p class="small" style="margin:0 0 6px">${esc(t("sn.why." + r.status))}</p>
      <details><summary>${esc(t("sn.obligations"))}</summary><p class="small">${esc((LIC_TABLE.obligations[r.cls] || LIC_TABLE.obligations.unknown)[LANG] || (LIC_TABLE.obligations[r.cls] || LIC_TABLE.obligations.unknown).en)}</p>${r.families.map(f => `<p class="small"><b>${esc(f)}:</b> ${esc(((LIC_TABLE.family_notes || {})[f] || {})[LANG] || ((LIC_TABLE.family_notes || {})[f] || {}).en || "")}</p>`).join("")}</details>
      <details><summary>${esc(t("sn.evidence", {n: r.findings.length}))}</summary>${r.findings.length ? `<div class="tablewrap"><table><tbody>${r.findings.map(f => `<tr><td>${esc(f.how === "spdx-tag" ? t("sn.how.tag") : t("sn.how.header"))}</td><td><code>${esc(f.id)}</code></td><td class="small">${esc(t("sn.line", {n: f.line}))} · ${esc(t("sn.conf." + f.conf))}</td><td class="small muted">${esc(f.text)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="small no">${esc(t("sn.none_found"))}</p>`}
      ${r.copyrights.length ? `<p class="small">${esc(t("sn.copyright"))}: ${esc(r.copyrights.join("; "))}</p>` : ""}</details></div>`;
    out.innerHTML = `<div class="kpis"><div class="kpi"><span class="muted small">${esc(t("sn.k.files"))}</span><b>${res.length}</b></div>${["compliant", "review", "noncompliant", "unknown"].map(k => `<div class="kpi"><span class="pill ${SN_STATUS_PILL[k]}">${esc(t("sn.status." + k))}</span><b>${count(k)}</b></div>`).join("")}</div>
      <div class="row" style="margin-bottom:10px"><button id="snNotice">⬇ ${esc(t("sn.notice"))}</button></div><div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(340px,1fr))">${res.map(card).join("")}</div>
      <p class="small muted">${esc(t("sn.policy_note"))}</p>`;
    document.getElementById("snNotice").onclick = () => downloadBlob(`NOTICE-snippets-${date}.txt`, snNotice(res, {date}), "text/plain");
  }
}

if (typeof module !== "undefined" && module.exports) module.exports = {snDetect, snAnalyze, snNotice, snClass, SN_MAX_FILES, SN_MAX_BYTES};
