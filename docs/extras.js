"use strict";
/* SBOM Explorer — data availability, evidence, feedback, upload, admin.
   Loaded after app.js (shares its globals: $app, esc, t, tn, loc, link, pill, stackBar, manifest, ...). */

/* ---------- collection server (optional) ---------- */
let API = null;  // set when /api/health answers: {upload_needs_token, max_bytes, ...}
/* user settings (Settings page, #/settings) live in localStorage; they override the defaults below and apply after a reload */
const userSetting = k => { try { return (JSON.parse(localStorage.getItem("sbom-settings") || "{}")[k] || "").trim(); } catch (_) { return ""; } };
const apiBase = () => { const b = userSetting("apiBase") || manifest?.settings?.api_base || ""; return b && !b.endsWith("/") ? b + "/" : b; };
const DEFAULT_WORKER_URL = "https://sbom-explorer-upload.sbomcra.workers.dev";  // set to your Cloudflare Worker URL when deployed (e.g. "https://sbom-explorer-upload.worker.dev")
const WORKER_URL = (userSetting("workerUrl") || DEFAULT_WORKER_URL).replace(/\/+$/, "");
const apiReady = (async () => {
  try {
    const r = await fetch(apiBase() + "api/health", {cache: "no-store"});
    if (r.ok) { const j = await r.json(); if (j && j.api) API = j; }
  } catch (_) { /* static hosting: no collection server */ }
})();

/* ---------- data availability ---------- */
const DQ_ORDER = ["osv", "nvd", "pending", "unmatched", "none"];
const DQ_COLOR = {osv: "var(--good)", nvd: "var(--good)", pending: "var(--med)", unmatched: "var(--high)", none: "var(--unk)"};
const CVE_GAPS = ["pending", "cve_blind", "no_cve_data", "no_cvss", "no_cve_id", "no_epss", "no_fix", "no_vex", "stale"];
const lastOf = v => v.history[v.history.length - 1];
const checkedOf = h => h.dq.osv + h.dq.nvd;

function gapText(g, part) {
  return t(`g.${g.id}.${part}`, {n: g.n ?? "—", of: g.of ?? "—", no_id: g.no_id ?? 0, unmatched: g.unmatched ?? 0});
}
function gapHtml(g) {
  return `<div class="act ${esc(g.prio)}"><div class="row" style="justify-content:space-between"><b>${esc(gapText(g, "t"))}</b>${pill(g.prio, t("prio." + g.prio))}</div>
    <div class="small">${esc(gapText(g, "d"))}</div><div class="small muted"><b>${esc(t("av.how"))}:</b> ${esc(gapText(g, "h"))}</div>
    <button class="gapBtn small" data-gap="${esc(g.id)}">${esc(t("av.report"))}</button></div>`;
}
function availabilityCard(p, v) {
  const h = lastOf(v), n = Math.max(h.components, 1), ds = v.data_sources || {};
  const bar = `<div class="bar">${DQ_ORDER.map(k => `<span style="width:${100 * h.dq[k] / n}%;background:${DQ_COLOR[k]}" title="${esc(t("st." + k))}: ${h.dq[k]}"></span>`).join("")}</div>`;
  const legend = DQ_ORDER.filter(k => h.dq[k]).map(k => `<span><b style="color:${DQ_COLOR[k]}">●</b> ${esc(t("st." + k))} ${h.dq[k]}</span>`).join(" &nbsp; ");
  const src = t("av.sources", {osv: ds.osv_asof || t("av.na"), nvd: ds.nvd_asof || t("av.na"), kev: ds.kev_day || t("av.na")});
  return `<div class="card" style="margin-top:14px" data-tour="avail"><h3>${esc(t("av.title"))}</h3><p class="small muted">${esc(t("av.lead"))}</p>
    <div class="small" style="margin:6px 0">${esc(t("av.cve_bar"))} — <b>${esc(t("av.checked", {a: checkedOf(h), b: h.components}))}</b></div>${bar}<div class="small muted" style="margin-top:4px">${legend}</div>
    <p class="small muted">${esc(src)}</p>
    ${v.data_gaps.length ? v.data_gaps.map(gapHtml).join("") : `<p class="ok">${esc(t("av.none_gaps"))}</p>`}</div>`;
}
const cveCell = (h, kind) => checkedOf(h) === 0 ? `<span class="muted">${esc(t("av.na"))}</span>` : String(kind === "open" ? h.open_total : h.vuln_total);

/* ---------- evidence tab ---------- */
const repoBlob = (p, path) => p.repo ? `https://github.com/${p.repo.slug}/blob/${p.repo.branch}/${path}` : "";
const fmtBytes = b => b > 1048576 ? (b / 1048576).toFixed(1) + " MB" : b > 1024 ? Math.round(b / 1024) + " kB" : b + " B";
function evidenceTab(p, v) {
  const h = lastOf(v), c = p.compliance, ds = v.data_sources || {};
  const row = (k, val) => `<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:6px 0"><span>${esc(k)}</span><b>${val}</b></div>`;
  const comp = c ? `<div class="card"><h3>${esc(t("ev.compliance"))}</h3>
    ${c.components ? row(t("ev.lic_text"), `${c.with_license_text} / ${c.components}`) + row(t("ev.copyright"), `${c.with_copyright} / ${c.components}`) : ""}
    ${c.scan_coverage ? row(t("ev.scan"), Object.entries(c.scan_coverage).map(([k, n]) => `${esc(k)} ${n}`).join(" · ")) : ""}
    ${c.drift_total != null ? row(t("ev.drift"), esc(t("ev.drift_v", {blocking: c.drift_blocking ?? 0, expected: c.drift_expected ?? 0, total: c.drift_total}))) : ""}
    ${c.enriched != null ? row(t("ev.enrich"), esc(t("ev.enrich_v", {enriched: c.enriched, failed: c.failed ?? 0}))) : ""}</div>` : "";
  const files = (p.evidence_files || []).map(f => {
    const href = f.exists ? repoBlob(p, f.path) : "";
    return `<tr><td>${esc(tn("ef.", f.id))}</td><td>${href ? `<a href="${esc(href)}" target="_blank" rel="noopener"><code>${esc(f.path)}</code></a>` : `<code>${esc(f.path)}</code>`}</td><td class="${f.exists ? "ok" : "no"}">${esc(t(f.exists ? "ev.present" : "ev.missing"))}</td><td class="small muted">${f.exists ? fmtBytes(f.bytes) : ""}</td></tr>`;
  }).join("");
  const defs = v.vuln_defs, ids = [...new Set((h.cve_pairs || []).map(x => x[0]))];
  const vexN = ds.vex_entries || 0, untri = ids.filter(i => !defs[i]?.vex).length;
  const states = Object.entries(ids.reduce((a, i) => { const s = defs[i]?.vex?.state; if (s) a[s] = (a[s] || 0) + 1; return a; }, {}));
  const vex = `<div class="card"><h3>${esc(t("ev.vex"))}</h3>
    <p class="small">${esc(vexN ? t("ev.vex_have", {n: vexN}) : t("ev.vex_none", {n: untri}))} ${states.map(([s, n]) => `<span class="badge">${esc(s)} ${n}</span>`).join(" ")}</p>
    <p class="small muted">${esc(t("ev.vex_how"))}</p><button id="vexDl" ${ids.length ? "" : "disabled"}>${esc(t("ev.vex_dl"))}</button></div>`;
  const links = (p.links || []).map(l => `<li><a href="${esc(l.url)}" target="_blank" rel="noopener">${esc(loc(l.label) || l.url)}</a></li>`).join("");
  const sec = p.contact?.security;
  const contact = sec ? `<p class="small">${sec.email ? `<a href="mailto:${esc(sec.email)}">${esc(sec.email)}</a>` : ""} ${sec.policy && repoBlob(p, sec.policy) ? `· <a href="${esc(repoBlob(p, sec.policy))}" target="_blank" rel="noopener">${esc(sec.policy)}</a>` : ""} ${sec.response ? `· ${esc(loc(sec.response))}` : ""}</p>` : "";
  const sel = [...v.history].reverse().map(x => `<option value="${esc(x.version)}">${esc(x.version)}</option>`).join("");
  return `<div class="grid">${comp}${vex}</div>
    ${files ? `<h3>${esc(t("ev.files"))}</h3><div class="tablewrap"><table><tbody>${files}</tbody></table></div>` : ""}
    <div class="card" style="margin-top:14px"><h3>${esc(t("ev.releasefiles"))} <select id="evRel">${sel}</select></h3><div id="evRelFiles" class="small"></div></div>
    <div class="grid" style="margin-top:14px"><div class="card"><h3>${esc(t("ev.links"))}</h3>${links ? `<ul class="small">${links}</ul>` : `<p class="small muted">${esc(t("ev.none"))}</p>`}</div>
    <div class="card"><h3>${esc(t("ev.contact"))}</h3>${contact || `<p class="small muted">${esc(t("ev.none"))}</p>`}</div></div>`;
}
function downloadBlob(name, text, type = "application/json") {
  const a = document.createElement("a"), url = URL.createObjectURL(new Blob([text], {type}));
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000);
}
function wireEvidence(p, v) {
  const rel = document.getElementById("evRel"), box = document.getElementById("evRelFiles");
  const draw = () => {
    const h = v.history.find(x => x.version === rel.value);
    box.innerHTML = (h.files || []).map(f => `<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:4px 0"><code>${esc(f.name)}</code><span class="muted">${fmtBytes(f.bytes)}</span></div>`).join("") || `<span class="muted">${esc(t("ev.none"))}</span>`;
  };
  rel.onchange = draw; draw();
  const dl = document.getElementById("vexDl");
  if (dl) dl.onclick = () => {
    const h = lastOf(v), seen = new Map();
    (h.cve_pairs || []).forEach(([id, key]) => { if (!seen.has(id)) seen.set(id, []); seen.get(id).push(key); });
    const doc = {bomFormat: "CycloneDX", specVersion: "1.5", version: 1,
      metadata: {timestamp: new Date().toISOString(), component: {type: "application", name: p.name, version: h.version}},
      vulnerabilities: [...seen].map(([id, refs]) => ({id, source: {name: v.vuln_defs[id]?.src === "nvd" ? "NVD" : v.vuln_defs[id]?.src === "euvd" ? "EUVD" : "OSV"},
        ...(v.vuln_defs[id]?.euvd ? {references: [{id: v.vuln_defs[id].euvd.id, source: {name: "EUVD", url: `https://euvd.enisa.europa.eu/vulnerability/${v.vuln_defs[id].euvd.id}`}}]} : {}),
        analysis: {state: v.vuln_defs[id]?.vex?.state || "in_triage"}, affects: refs.map(ref => ({ref})) }))};
    downloadBlob(`${p.id}-${h.version}.vex-template.cdx.json`, JSON.stringify(doc, null, 2));
  };
}

/* ---------- wiring called by app.js after a product tab rendered ---------- */
let pageCtx = {};
function wireExtras(p, vid, v, tab) {
  pageCtx = {product: p.id, variant: vid, version: lastOf(v).version};
  document.querySelectorAll(".gapBtn").forEach(b => b.onclick = () => {
    const id = b.dataset.gap, g = v.data_gaps.find(x => x.id === id);
    openFeedback({category: CVE_GAPS.includes(id) ? "missing_cve" : "missing_component", message: `[${p.name} · ${v.label} ${lastOf(v).version}] ${g ? gapText(g, "t") : id}\n`});
  });
  if (tab === "evidence") wireEvidence(p, v);
  if (tab === "quality") wireQuality(p, vid, v);
}

/* ---------- feedback ---------- */
const FB_CATS = ["missing_cve", "missing_component", "wrong_data", "translation", "bug", "idea", "other"];
function closeFeedback() { document.getElementById("fbModal")?.remove(); document.removeEventListener("keydown", closeFeedback.key); }
function openFeedback(pref = {}) {
  closeFeedback();
  const route = location.hash || "#/";
  const m = document.createElement("div");
  m.id = "fbModal"; m.className = "modal"; m.setAttribute("role", "dialog"); m.setAttribute("aria-modal", "true");
  m.innerHTML = `<div class="box"><h3 style="margin-top:0">${esc(t("fb.title"))}</h3>
    <label class="blk">${esc(t("fb.category"))}<select id="fbCat">${FB_CATS.map(c => `<option value="${c}" ${c === (pref.category || "other") ? "selected" : ""}>${esc(t("fb.cat." + c))}</option>`).join("")}</select></label>
    <label class="blk">${esc(t("fb.message"))}<textarea id="fbMsg" rows="6" maxlength="4000"></textarea></label>
    <label class="blk">${esc(t("fb.contact"))}<input id="fbContact" type="text" maxlength="200"></label>
    <label class="blk row"><input id="fbCtx" type="checkbox" checked> <span class="small">${esc(t("fb.context", {route}))}</span></label>
    <div id="fbOut" class="small" style="margin:8px 0"></div>
    <div class="row" style="justify-content:flex-end"><button id="fbClose">${esc(t("fb.cancel"))}</button><button id="fbSend" class="primary">${esc(t("fb.send"))}</button></div></div>`;
  document.body.appendChild(m);
  const msg = m.querySelector("#fbMsg"), out = m.querySelector("#fbOut");
  msg.value = pref.message || ""; msg.focus(); msg.setSelectionRange(msg.value.length, msg.value.length);
  m.addEventListener("click", e => { if (e.target === m) closeFeedback(); });
  m.querySelector("#fbClose").onclick = closeFeedback;
  closeFeedback.key = e => { if (e.key === "Escape") closeFeedback(); };
  document.addEventListener("keydown", closeFeedback.key);
  const payload = () => ({category: m.querySelector("#fbCat").value, message: msg.value.trim(), contact: m.querySelector("#fbContact").value.trim(), lang: LANG,
    ...(m.querySelector("#fbCtx").checked ? {route, ...pageCtx} : {})});
  const offline = d => {
    const text = `[${d.category}] ${d.message}\n\n— ${d.route || ""} ${d.product || ""} ${d.variant || ""} ${d.version || ""} · ${d.lang}`;
    const fb = manifest?.settings?.feedback || {};
    const gh = fb.github ? `https://github.com/${fb.github}/issues/new?title=${encodeURIComponent("[SBOM Explorer] " + t("fb.cat." + d.category))}&body=${encodeURIComponent(text)}` : "";
    const mail = fb.email ? `mailto:${fb.email}?subject=${encodeURIComponent("SBOM Explorer feedback")}&body=${encodeURIComponent(text)}` : "";
    out.innerHTML = `${esc(t("fb.offline"))}<div class="row" style="margin-top:6px">${gh ? `<a class="btn" target="_blank" rel="noopener" href="${esc(gh)}">${esc(t("fb.github"))}</a>` : ""}${mail ? `<a class="btn" href="${esc(mail)}">${esc(t("fb.email"))}</a>` : ""}<button id="fbCopy">${esc(t("fb.copy"))}</button></div>`;
    out.querySelector("#fbCopy").onclick = async e => { try { await navigator.clipboard.writeText(text); e.target.textContent = t("fb.copied"); } catch (_) { msg.select(); } };
  };
  m.querySelector("#fbSend").onclick = async () => {
    const d = payload();
    if (d.message.length < 3) { out.textContent = t("fb.short"); return; }
    await apiReady;
    if (!API) { offline(d); return; }
    try {
      const r = await fetch(apiBase() + "api/feedback", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(d)});
      const j = await r.json();
      if (r.ok && j.ok) { out.innerHTML = `<b class="ok">${esc(t("fb.thanks", {id: j.id}))}</b>`; msg.value = ""; }
      else out.innerHTML = `<span class="no">${esc(t("fb.error", {msg: j.error || r.status}))}</span>`;
    } catch (e) { out.innerHTML = `<span class="no">${esc(t("fb.error", {msg: e.message}))}</span>`; offline(d); }
  };
}

/* ---------- upload ---------- */
const OSV_PREFIX = ["pkg:cargo/", "pkg:pypi/", "pkg:npm/", "pkg:maven/", "pkg:golang/", "pkg:nuget/", "pkg:gem/", "pkg:hex/", "pkg:composer/", "pkg:pub/", "pkg:swift/"];
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$/;
function localSummary(doc) {
  const spdx = doc && typeof doc === "object" && "spdxVersion" in doc;
  if (!doc || typeof doc !== "object" || !(spdx || "bomFormat" in doc)) throw new Error("not sbom");
  let comps;
  if (spdx) { const ds = new Set([...(doc.documentDescribes || []), ...(doc.relationships || []).filter(r => r.relationshipType === "DESCRIBES").map(r => r.relatedSpdxElement)]); comps = (doc.packages || []).filter(x => !ds.has(x.SPDXID)); }
  else comps = doc.components || [];
  const ref = (c, ...types) => ((c.externalRefs || []).find(r => types.includes(String(r.referenceType).toLowerCase())) || {}).referenceLocator || "";
  const purl = c => spdx ? ref(c, "purl") : c.purl || "", cpe = c => spdx ? ref(c, "cpe23type") : c.cpe || "";
  const n = comps.length, pct = k => n ? Math.round(100 * comps.filter(k).length / n) : 0;
  const checkable = comps.filter(c => (purl(c) && OSV_PREFIX.some(x => purl(c).startsWith(x))) || (cpe(c).startsWith("cpe:2.3:") && cpe(c).split(":").length >= 13)).length;
  return {format: spdx ? "SPDX" : "CycloneDX", spec: spdx ? doc.spdxVersion : doc.specVersion, n, checkable, blind: n - checkable,
    deps: spdx ? (doc.relationships || []).some(r => !["DESCRIBES", "DESCRIBED_BY"].includes(r.relationshipType)) : !!(doc.dependencies || []).length,
    ts: !!(spdx ? doc.creationInfo?.created : doc.metadata?.timestamp),
    lic: pct(c => spdx ? (c.licenseConcluded || c.licenseDeclared) && !/^NOASSERTION|NONE$/i.test(c.licenseConcluded || c.licenseDeclared) : (c.licenses || []).length),
    sup: pct(c => spdx ? c.supplier && !/NOASSERTION/i.test(c.supplier) : c.supplier || c.publisher || c.author), hash: pct(c => (c.hashes || c.checksums || []).length)};
}
function previewHtml(s) {
  const li = (ok, txt) => `<li class="${ok ? "ok" : "no"}">${ok ? "✔" : "✖"} ${esc(txt)}</li>`;
  return `<ul class="small" style="list-style:none;padding:0">${li(true, t("up.pv.format", {f: s.format, s: s.spec}))}${li(s.n > 0, t("up.pv.comps", {n: s.n}))}
    ${li(s.checkable === s.n && s.n > 0, t("up.pv.cve_ok", {a: s.checkable, b: s.n}))}${s.blind ? li(false, t("up.pv.cve_blind", {n: s.blind})) : ""}
    ${li(s.deps, t(s.deps ? "up.pv.deps_yes" : "up.pv.deps_no"))}${li(s.ts, t(s.ts ? "up.pv.ts_yes" : "up.pv.ts_no"))}
    ${li(s.lic >= 90, t("up.pv.lic", {p: s.lic}))}${li(s.sup >= 90, t("up.pv.sup", {p: s.sup}))}${li(s.hash >= 90, t("up.pv.hash", {p: s.hash}))}</ul>`;
}
async function serverQuality(sbom) {
  await apiReady;
  if (!API) return "";
  try {
    const r = await fetch(apiBase() + "api/validate", {method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({schema: "sbom-explorer-submission/1", product: {id: "preview", name: "preview", type: "other"}, variant: {id: "preview"}, version: "0", sbom})});
    const j = await r.json(), qv = j.summary?.quality;
    if (!qv) return "";
    const st = k => t("q.st." + qv.profiles[k]);
    return `<div class="row" style="align-items:center;gap:10px;margin-top:8px">${gradeChip(qv.grade)}<b>${esc(t("up.pv.quality", {s: qv.score.toFixed(1), g: qv.grade}))}</b></div>
      <div class="small">${esc(t("up.pv.profiles", {n: st("ntia"), b: st("bsi"), f: st("fsct")}))}</div>
      ${qv.weakest.length ? `<div class="small muted">${esc(t("up.pv.weak", {list: qv.weakest.map(w => t("qf." + w.id)).join("; ")}))}</div>` : ""}`;
  } catch (_) { return ""; }
}
const readJSON = file => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => { try { res(JSON.parse(r.result)); } catch (e) { rej(e); } }; r.onerror = rej; r.readAsText(file); });
const readText = file => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsText(file); });
function parseCSV(text) {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  const headers = lines[0].split(",").map(h => h.trim().replace(/^"|"$/g, ""));
  const out = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]; if (!line.trim()) continue;
    const values = []; let cur = "", inQ = false;
    for (let j = 0; j < line.length; j++) {
      const ch = line[j], next = line[j + 1];
      if (ch === '"') { if (inQ && next === '"') { cur += '"'; j++; continue; } inQ = !inQ; continue; }
      if (ch === ',' && !inQ) { values.push(cur.trim().replace(/^"|"$/g, "")); cur = ""; continue; }
      cur += ch;
    }
    values.push(cur.trim().replace(/^"|"$/g, ""));
    const obj = {}; headers.forEach((h, idx) => obj[h] = values[idx] || ""); out.push(obj);
  }
  return out;
}

async function uploadView() {
  $crumb.textContent = t("up.title");
  await apiReady;
  let products = manifest.products.map(p => ({id: p.id, name: p.name, uploadable: true, variants: Object.entries(p.variants).map(([id, x]) => ({id, label: x.label}))}));
  if (API) { try { products = (await (await fetch(apiBase() + "api/products")).json()).products || products; } catch (_) {} }
  const types = ["desktop", "mobile", "web", "embedded", "server", "library", "other"];
  $app.innerHTML = `<h2 style="margin:6px 0 4px">${esc(t("up.title"))}</h2><p class="muted">${esc(t("up.lead"))}</p>
  <div class="card ${API ? "" : WORKER_URL ? "" : "warn"}"><b>${esc(t(API ? "up.mode_api" : WORKER_URL ? "up.mode_worker" : "up.mode_offline"))}</b></div>
  <div class="card" style="margin-top:14px"><form id="upForm" autocomplete="off">
   <label class="blk">${esc(t("up.product"))}<select id="upProd">${products.map(p => `<option value="${esc(p.id)}" ${p.uploadable ? "" : "disabled"}>${esc(p.name)}${p.uploadable ? "" : " 🔒"}</option>`).join("")}<option value="__new">${esc(t("up.new_product"))}</option></select></label>
   <div id="upNew" hidden class="grid">
     <label class="blk">${esc(t("up.pid"))}<input id="upPid" maxlength="61" placeholder="my-app"></label>
     <label class="blk">${esc(t("up.pname"))}<input id="upName" maxlength="80"></label>
     <label class="blk">${esc(t("up.ptype"))}<select id="upType">${types.map(x => `<option value="${x}">${esc(typeLabel(x))}</option>`).join("")}</select></label>
     <label class="blk">${esc(t("up.tagline_en"))}<input id="upTagEn" maxlength="200"></label>
     <label class="blk">${esc(t("up.tagline_pl"))}<input id="upTagPl" maxlength="200"></label>
     <label class="blk">${esc(t("up.website"))}<input id="upWeb" maxlength="200" placeholder="https://"></label></div>
   <label class="blk">${esc(t("up.variant"))}<select id="upVar"></select></label>
   <div id="upNewVar" hidden class="grid"><label class="blk">${esc(t("up.vid"))}<input id="upVid" maxlength="61" placeholder="android"></label><label class="blk">${esc(t("up.vlabel"))}<input id="upVlabel" maxlength="40"></label></div>
   <label class="blk">${esc(t("up.version"))}<input id="upVer" maxlength="61" placeholder="2.4.0"></label>
   <label class="blk">${esc(t("up.file"))}<input id="upFile" type="file" accept=".json,application/json"></label>
   <div id="upPreview"></div>
   <label class="blk">${esc(t("up.vexfile"))}<input id="upVex" type="file" accept=".json,application/json"></label>
   <label class="blk">${esc(t("up.contact"))}<input id="upContact" maxlength="200"></label>
   <label class="blk" id="upTokRow" ${API?.upload_needs_token ? "" : "hidden"}>${esc(t("up.token"))}<input id="upTok" type="password" autocomplete="off"></label>
   <div id="upErr" class="no small"></div><div class="row"><button type="submit" class="primary" id="upGo">${esc(t(API ? "up.submit" : WORKER_URL ? "up.submit" : "up.download"))}</button></div>
  </form><div id="upJob" style="margin-top:12px"></div></div>
  <div class="card" style="margin-top:14px"><h3 style="margin-top:0">${esc(t("csv.title"))}</h3><p class="small muted">${esc(t("csv.lead"))}</p>
   <div class="row" style="margin-bottom:10px"><a class="btn" href="data/import-template.csv" download="sbom-explorer-products.csv">${esc(t("csv.template"))}</a></div>
   <form id="csvForm" autocomplete="off">
     <label class="blk">${esc(t("csv.file"))}<input id="csvFile" type="file" accept=".csv,text/csv"></label>
     <div id="csvPreview"></div>
     <label class="blk" id="csvTokRow" ${API?.upload_needs_token ? "" : "hidden"}>${esc(t("up.token"))}<input id="csvTok" type="password" autocomplete="off"></label>
     <div id="csvErr" class="no small"></div>
     <div class="row"><button type="submit" class="primary" id="csvGo">${esc(t(API ? "up.submit" : "csv.download_patch"))}</button></div>
   </form>
   <div id="csvJob" style="margin-top:12px"></div>
  </div>`;
  const $ = id => document.getElementById(id);
  const state = {sbom: null, vex: null};
  const refreshVariants = () => {
    const p = products.find(x => x.id === $("upProd").value);
    $("upNew").hidden = $("upProd").value !== "__new";
    $("upVar").innerHTML = (p ? p.variants : []).map(v => `<option value="${esc(v.id)}">${esc(v.label)}</option>`).join("") + `<option value="__new">${esc(t("up.new_variant"))}</option>`;
    $("upNewVar").hidden = $("upVar").value !== "__new";
  };
  $("upProd").onchange = refreshVariants; $("upVar").onchange = () => { $("upNewVar").hidden = $("upVar").value !== "__new"; };
  const firstOk = products.find(p => p.uploadable); if (firstOk) $("upProd").value = firstOk.id;
  refreshVariants();
  $("upFile").onchange = async () => {
    state.sbom = null; $("upPreview").innerHTML = "";
    const f = $("upFile").files[0]; if (!f) return;
    try {
      state.sbom = await readJSON(f);
      $("upPreview").innerHTML = `<div class="card"><h4 style="margin:0 0 6px">${esc(t("up.preview"))}</h4>${previewHtml(localSummary(state.sbom))}<div id="upQ"></div></div>`;
      serverQuality(state.sbom).then(h => { const el = $("upQ"); if (el) el.innerHTML = h; });
    }
    catch (_) { state.sbom = null; $("upPreview").innerHTML = `<p class="no small">${esc(t("up.bad_json"))}</p>`; }
  };
  $("upVex").onchange = async () => { state.vex = null; const f = $("upVex").files[0]; if (f) { try { state.vex = await readJSON(f); } catch (_) { $("upErr").textContent = t("up.bad_json"); } } };
  $("upForm").onsubmit = async ev => {
    ev.preventDefault();
    const err = []; const isNew = $("upProd").value === "__new", newVar = $("upVar").value === "__new";
    const pid = isNew ? $("upPid").value.trim() : $("upProd").value, vid = newVar ? $("upVid").value.trim() : $("upVar").value;
    if (!ID_RE.test(pid)) err.push(t("up.pid")); if (isNew && !$("upName").value.trim()) err.push(t("up.pname"));
    if (!vid || !ID_RE.test(vid)) err.push(t("up.vid")); if (!ID_RE.test($("upVer").value.trim())) err.push(t("up.version")); if (!state.sbom) err.push(t("up.file"));
    if (err.length) { $("upErr").textContent = t("up.errors") + ": " + err.join(", "); return; }
    $("upErr").textContent = "";
    const known = products.find(x => x.id === pid);
    const doc = {schema: "sbom-explorer-submission/1",
      product: isNew ? {id: pid, name: $("upName").value.trim(), type: $("upType").value, website: $("upWeb").value.trim(), tagline: {en: $("upTagEn").value.trim(), pl: $("upTagPl").value.trim()}} : {id: pid, name: known?.name || pid, type: "other"},
      variant: {id: vid, label: newVar ? ($("upVlabel").value.trim() || vid) : ""}, version: $("upVer").value.trim(), sbom: state.sbom,
      ...(state.vex ? {vex: state.vex} : {}), ...($("upContact").value.trim() ? {submitter: {contact: $("upContact").value.trim()}} : {})};
    if (!API) {
      if (WORKER_URL) {
        $("upGo").disabled = true; $("upJob").textContent = t("up.state.queued");
        try {
          const r = await fetch(WORKER_URL + "/api/upload", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(doc)});
          const j = await r.json();
          if (!r.ok) throw new Error(j.error || r.status);
          $("upJob").innerHTML = `<p class="ok small">${esc(t("up.worker_pr", {pr: j.pr_number}))}</p><p class="small muted"><a href="${esc(j.pr_url)}" target="_blank" rel="noopener">${esc(j.pr_url)} ↗</a></p>`;
        } catch (e) { $("upErr").textContent = t("up.worker_error", {err: e.message}); $("upJob").textContent = ""; }
        $("upGo").disabled = false; return;
      }
      downloadBlob(`submission-${pid}-${vid}-${doc.version}.json`, JSON.stringify(doc)); $("upJob").innerHTML = `<p class="small muted">python tools/import_sbom.py --envelope submission-${esc(pid)}-${esc(vid)}-${esc(doc.version)}.json</p>`; return;
    }
    $("upGo").disabled = true; $("upJob").textContent = t("up.state.queued");
    try {
      const headers = {"Content-Type": "application/json", ...($("upTok").value ? {Authorization: "Bearer " + $("upTok").value} : {})};
      const r = await fetch(apiBase() + "api/submissions", {method: "POST", headers, body: JSON.stringify(doc)});
      const j = await r.json();
      if (!r.ok || !j.ok) { $("upErr").textContent = j.error || r.status; $("upJob").textContent = ""; $("upGo").disabled = false; return; }
      pollJob(j.job, pid, vid);
    } catch (e) { $("upErr").textContent = e.message; $("upJob").textContent = ""; $("upGo").disabled = false; }
  };
  async function pollJob(job, pid, vid) {
    for (let i = 0; i < 900; i++) {
      const j = (await (await fetch(apiBase() + "api/jobs/" + job)).json()).job;
      $("upJob").innerHTML = `<b>${esc(t("up.state." + j.state))}</b>` + (j.state === "failed" ? `<pre class="small">${esc(j.log)}</pre>` : "");
      if (j.state === "done") { manifest = null; delete cache[pid]; $("upJob").innerHTML += ` <a class="btn primary" href="${link(["p", pid, vid])}">${esc(t("up.open"))}</a>`; break; }
      if (j.state === "failed") break;
      await new Promise(r => setTimeout(r, 2000));
    }
    $("upGo").disabled = false;
  }
  let csvRows = null;
  $("csvFile").onchange = async () => {
    csvRows = null; $("csvPreview").innerHTML = ""; $("csvErr").textContent = "";
    const f = $("csvFile").files[0]; if (!f) return;
    try {
      const text = await readText(f);
      csvRows = parseCSV(text);
      if (!csvRows.length) { $("csvPreview").innerHTML = `<p class="no small">${esc(t("csv.empty"))}</p>`; return; }
      const cols = Object.keys(csvRows[0]);
      const preview = csvRows.slice(0, 5).map(r => `<tr>${cols.map(c => `<td>${esc(r[c] || "")}</td>`).join("")}</tr>`).join("");
      $("csvPreview").innerHTML = `<div class="tablewrap"><table><thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${preview}</tbody></table><p class="small muted">${esc(t("csv.rows", {n: csvRows.length}))}</p></div>`;
    } catch (e) { csvRows = null; $("csvPreview").innerHTML = `<p class="no small">${esc(t("csv.bad"))}</p>`; }
  };
  $("csvForm").onsubmit = async ev => {
    ev.preventDefault();
    if (!csvRows) { $("csvErr").textContent = t("csv.bad"); return; }
    $("csvErr").textContent = "";
    if (!API) {
      const patch = csvRows.map(r => {
        const obj = {};
        for (const [k, v] of Object.entries(r)) { const nk = k.toLowerCase().replace(/\s+/g, "_").replace(/-/g, "_"); if (v.trim()) obj[nk] = v.trim(); }
        return obj;
      });
      downloadBlob("products-patch.json", JSON.stringify(patch, null, 2));
      $("csvJob").innerHTML = `<p class="small muted">python tools/import_products_csv.py --patch products-patch.json</p>`; return;
    }
    $("csvGo").disabled = true; $("csvJob").textContent = t("up.state.queued");
    try {
      const headers = {"Content-Type": "application/json", ...($("csvTok").value ? {Authorization: "Bearer " + $("csvTok").value} : {})};
      const r = await fetch(apiBase() + "api/import-csv", {method: "POST", headers, body: JSON.stringify({rows: csvRows})});
      const j = await r.json();
      if (!r.ok || !j.ok) { $("csvErr").textContent = j.error || r.status; $("csvJob").textContent = ""; $("csvGo").disabled = false; return; }
      for (let i = 0; i < 900; i++) {
        const st = (await (await fetch(apiBase() + "api/jobs/" + j.job)).json()).job;
        $("csvJob").innerHTML = `<b>${esc(t("up.state." + st.state))}</b>` + (st.state === "failed" ? `<pre class="small">${esc(st.log)}</pre>` : "");
        if (st.state === "done") { manifest = null; $("csvJob").innerHTML += ` <a class="btn primary" href="${link([])}">${esc(t("csv.open_home"))}</a>`; break; }
        if (st.state === "failed") break;
        await new Promise(r => setTimeout(r, 2000));
      }
      $("csvGo").disabled = false;
    } catch (e) { $("csvErr").textContent = e.message; $("csvJob").textContent = ""; $("csvGo").disabled = false; }
  };
}

/* ---------- admin: collected feedback and uploads ---------- */
async function adminView() {
  $crumb.textContent = t("adm.title");
  await apiReady;
  if (!API) { $app.innerHTML = `<h2>${esc(t("adm.title"))}</h2><p class="muted">${esc(t("adm.noapi"))}</p>`; return; }
  let tok = ""; try { tok = sessionStorage.getItem("adm") || ""; } catch (_) {}
  $app.innerHTML = `<h2 style="margin:6px 0 4px">${esc(t("adm.title"))}</h2>
   <div class="row"><input id="admTok" type="password" placeholder="${esc(t("adm.token"))}" value="${esc(tok)}" autocomplete="off"><button id="admLoad" class="primary">${esc(t("adm.load"))}</button><button id="admMd">${esc(t("adm.md"))}</button></div>
   <div id="admOut" style="margin-top:12px"></div>`;
  const hdr = () => ({Authorization: "Bearer " + document.getElementById("admTok").value});
  const get = async path => { const r = await fetch(apiBase() + path, {headers: hdr()}); if (r.status === 401) throw new Error(t("adm.denied")); return r; };
  const load = async () => {
    const out = document.getElementById("admOut");
    try {
      try { sessionStorage.setItem("adm", document.getElementById("admTok").value); } catch (_) {}
      const fb = (await (await get("api/feedback")).json()).feedback, sb = (await (await get("api/submissions")).json()).submissions;
      const stOpt = cur => ["new", "triaged", "done", "wont_fix"].map(s => `<option value="${s}" ${s === cur ? "selected" : ""}>${esc(t("adm.st." + s))}</option>`).join("");
      out.innerHTML = `<h3>${esc(t("adm.feedback"))} (${fb.length})</h3>${fb.length ? `<div class="tablewrap"><table><thead><tr><th>#</th><th></th><th></th><th></th><th></th></tr></thead><tbody>${fb.map(f => `<tr><td>${f.id}</td><td class="small">${esc(f.ts.slice(0, 16))}<br><span class="badge">${esc(f.category)}</span></td><td class="small">${esc(f.message)}<br><span class="muted">${esc(f.route)} ${esc(f.product)} ${esc(f.version)} ${esc(f.contact)}</span></td><td><select data-id="${f.id}" class="stSel">${stOpt(f.status)}</select></td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">${esc(t("adm.none"))}</p>`}
        <h3>${esc(t("adm.submissions"))} (${sb.length})</h3>${sb.length ? `<div class="tablewrap"><table><tbody>${sb.map(s => `<tr><td>${s.id}</td><td class="small">${esc(s.ts.slice(0, 16))}</td><td>${esc(s.product)} ${esc(s.variant || "")} ${esc(s.version || "")}</td><td class="small">${esc(s.format || "")} ${s.components ?? ""}</td><td class="${s.status === "rejected" ? "no" : "ok"} small">${esc(s.status)} <span class="muted">${esc(s.message || "")}</span></td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">${esc(t("adm.none"))}</p>`}`;
      out.querySelectorAll(".stSel").forEach(s => s.onchange = () => fetch(apiBase() + "api/feedback/" + s.dataset.id, {method: "POST", headers: {...hdr(), "Content-Type": "application/json"}, body: JSON.stringify({status: s.value})}));
    } catch (e) { out.innerHTML = `<p class="no">${esc(e.message)}</p>`; }
  };
  document.getElementById("admLoad").onclick = load;
  document.getElementById("admMd").onclick = async () => { try { const md = await (await get("api/feedback?format=md")).text(); await navigator.clipboard.writeText(md); } catch (e) { document.getElementById("admOut").innerHTML = `<p class="no">${esc(e.message)}</p>`; } };
  if (tok) load();
}
