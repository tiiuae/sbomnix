"use strict";
/* SBOM Explorer — package review: data stewards, "possibly defective" flags, CISO page (#/ciso), quick check (#/check).
   State lives in this browser (localStorage "sbom-review"); a CISO link carries the flags inside the URL (no server).
   Loaded after settings.js. Shares globals: $app, $crumb, esc, t, product, link, SEV, pill, downloadBlob, parseHash. */

const REASONS = ["defective", "unmaintained", "suspicious", "licence", "other"];
let CUR = null;  // {pid, vid, p, v} of the product page being shown

/* ---------- store ---------- */
const loadReview = () => { try { const r = JSON.parse(localStorage.getItem("sbom-review") || "{}"); return {flags: r.flags || {}, stewards: r.stewards || {}, by: r.by || ""}; } catch (_) { return {flags: {}, stewards: {}, by: ""}; } };
let review = loadReview();
const saveReview = () => { try { localStorage.setItem("sbom-review", JSON.stringify(review)); } catch (_) { /* storage blocked: state lasts until reload */ } refreshCisoBtn(); };
const flagKey = (pid, vid, x) => `${pid}|${vid}|${x[0]}@${x[1]}`;
const stewKey = (pid, x) => `${pid}|${x[0]}`;
const stewardOf = (pid, x) => review.stewards[stewKey(pid, x)] || "";
const flagOf = (pid, vid, x) => review.flags[flagKey(pid, vid, x)];
function refreshCisoBtn() {
  const b = document.getElementById("cisoBtn"); if (!b) return;
  const n = Object.keys(review.flags).length; b.textContent = "🛡 " + t("nav.ciso") + (n ? ` (${n})` : "");
}

/* ---------- modal (native <dialog>) ---------- */
function askModal({title, fields, removeLabel}) {
  return new Promise(resolve => {
    const d = document.createElement("dialog"); d.className = "rev-dlg";
    d.innerHTML = `<form method="dialog"><h3 style="margin-top:0">${esc(title)}</h3>${fields.map(f => `<label class="blk">${esc(f.label)}${f.options
      ? `<select name="${f.id}">${f.options.map(o => `<option value="${esc(o[0])}" ${o[0] === f.value ? "selected" : ""}>${esc(o[1])}</option>`).join("")}</select>`
      : `<input name="${f.id}" value="${esc(f.value || "")}" maxlength="${f.max || 200}" autocomplete="off">`}</label>`).join("")}
      <div class="row" style="margin-top:12px"><button class="primary" value="ok">${esc(t("rev.save"))}</button><button value="cancel" formnovalidate>${esc(t("rev.cancel"))}</button>${removeLabel ? `<button value="remove" class="linkish no">${esc(removeLabel)}</button>` : ""}</div></form>`;
    document.body.appendChild(d);
    d.addEventListener("close", () => { const fd = new FormData(d.querySelector("form")), out = {}; fields.forEach(f => out[f.id] = (fd.get(f.id) || "").toString().trim()); const rv = d.returnValue; d.remove(); resolve(rv === "ok" ? out : rv === "remove" ? {_remove: true} : null); });
    d.showModal(); (d.querySelector("input,select") || d).focus();
  });
}
const reasonOpts = () => REASONS.map(r => [r, t("rev.reason." + r)]);

/* ---------- Components tab hooks (called from app.js) ---------- */
const STEWARD_STATEMENT = () => `<div class="card warn" style="margin-bottom:14px"><h3 style="margin:0 0 6px">🧭 ${esc(t("rev.stew.title"))}</h3><p class="small" style="margin:0">${esc(t("rev.stew.statement"))}</p>
  <p class="small" style="margin:8px 0 0"><b id="stewKpi"></b></p></div>`;
function updateStewardKpi(rows) {
  const el = document.getElementById("stewKpi"); if (!el || !CUR) return;
  const un = CUR.v.components.filter(x => !stewardOf(CUR.pid, x)).length;
  el.textContent = t("rev.stew.kpi", {n: CUR.v.components.length - un, total: CUR.v.components.length, un});
}
function reviewHeadCells() { return `<th>${esc(t("rev.steward"))}</th><th>${esc(t("rev.flag"))}</th>`; }
function reviewCells(x) {
  const s = stewardOf(CUR.pid, x), f = flagOf(CUR.pid, CUR.vid, x);
  return `<td><button class="linkish stew" data-n="${esc(x[0])}" data-v="${esc(x[1])}" title="${esc(t("rev.steward_set"))}">${s ? esc(s) : `<span class="no">⚠ ${esc(t("rev.none"))}</span>`}</button></td>
    <td><button class="flagbtn ${f ? "on" : ""}" data-n="${esc(x[0])}" data-v="${esc(x[1])}" title="${esc(f ? t("rev.reason." + f.reason) + (f.note ? ": " + f.note : "") : t("rev.flag_add"))}" aria-pressed="${!!f}">⚑${f ? " " + esc(t("rev.reason." + f.reason)) : ""}</button></td>`;
}
function wireReview(tbody, redraw) {
  const comp = (n, v) => CUR.v.components.find(x => x[0] === n && x[1] === v);
  tbody.onclick = async e => {
    const sb = e.target.closest(".stew"), fb = e.target.closest(".flagbtn");
    if (sb) {
      const x = comp(sb.dataset.n, sb.dataset.v); if (!x) return;
      const r = await askModal({title: `${t("rev.steward")}: ${x[0]}`, fields: [{id: "who", label: t("rev.steward_who"), value: stewardOf(CUR.pid, x)}], removeLabel: stewardOf(CUR.pid, x) ? t("rev.steward_clear") : ""});
      if (!r) return; if (r._remove || !r.who) delete review.stewards[stewKey(CUR.pid, x)]; else review.stewards[stewKey(CUR.pid, x)] = r.who;
      saveReview(); redraw();
    } else if (fb) {
      const x = comp(fb.dataset.n, fb.dataset.v); if (!x) return; const cur = flagOf(CUR.pid, CUR.vid, x);
      const r = await askModal({title: `⚑ ${x[0]} ${x[1]}`, fields: [{id: "reason", label: t("rev.reason"), options: reasonOpts(), value: cur?.reason || "defective"}, {id: "note", label: t("rev.note"), value: cur?.note || "", max: 300}], removeLabel: cur ? t("rev.flag_remove") : ""});
      if (!r) return; if (r._remove) delete review.flags[flagKey(CUR.pid, CUR.vid, x)]; else review.flags[flagKey(CUR.pid, CUR.vid, x)] = {reason: r.reason, note: r.note, ts: cur?.ts || new Date().toISOString().slice(0, 10)};
      saveReview(); redraw();
    }
  };
}
const reviewFilter = () => `<select id="cfilter"><option value="">${esc(t("rev.f.all"))}</option><option value="nosteward">${esc(t("rev.f.nosteward"))}</option><option value="flagged">${esc(t("rev.f.flagged"))}</option></select>`;
const reviewMatches = (f, x) => !f || (f === "nosteward" ? !stewardOf(CUR.pid, x) : !!flagOf(CUR.pid, CUR.vid, x));
function bulkSteward(rows, redraw) {
  return async () => {
    const r = await askModal({title: t("rev.bulk", {n: rows().length}), fields: [{id: "who", label: t("rev.steward_who")}]}); if (!r || !r.who) return;
    rows().forEach(x => { if (!stewardOf(CUR.pid, x)) review.stewards[stewKey(CUR.pid, x)] = r.who; }); saveReview(); redraw();
  };
}

/* ---------- severity facts for a flagged component ---------- */
async function factsFor(pid, vid, name, ver) {
  const out = {sev: "unknown", cves: 0, exploited: false, known: false, euvd: ""};
  try {
    const p = await product(pid), v = p.variants[vid] || Object.values(p.variants)[0], last = v.history[v.history.length - 1], label = `${name}@${ver}`;
    const ids = [...new Set((last.cve_pairs || []).filter(x => x[3] === label).map(x => x[0]))];
    out.known = true; out.cves = ids.length; out.pname = p.name;
    for (const id of ids) { const d = v.vuln_defs[id] || {}; if (SEV.indexOf(d.sev || "unknown") < SEV.indexOf(out.sev)) out.sev = d.sev; if (d.kev || d.euvd?.exploited) out.exploited = true; if (d.euvd?.id && !out.euvd) out.euvd = d.euvd.id; }
    if (!ids.length) out.sev = "none";
  } catch (_) { /* product not on this site */ }
  return out;
}

/* ---------- CISO page ---------- */
const b64enc = o => btoa(unescape(encodeURIComponent(JSON.stringify(o)))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64dec = s => JSON.parse(decodeURIComponent(escape(atob(s.replace(/-/g, "+").replace(/_/g, "/")))));
function decodeShared(s) {
  try { const o = b64dec(s); if (!Array.isArray(o.f) || o.f.length > 500) return null;
    return {by: String(o.by || "").slice(0, 80), flags: Object.fromEntries(o.f.filter(a => Array.isArray(a) && typeof a[0] === "string").map(a => [a[0].slice(0, 200), {reason: REASONS.includes(a[1]) ? a[1] : "other", note: String(a[2] || "").slice(0, 300), steward: String(a[3] || "").slice(0, 80), ts: String(a[4] || "").slice(0, 10), n: Number.isFinite(a[5]) ? a[5] : undefined}]))}; } catch (_) { return null; }
}
const csvCell = x => `"${String(x ?? "").replace(/"/g, '""')}"`;

async function cisoView(q) {
  $crumb.textContent = t("ciso.title");
  const shared = q.get("d") ? decodeShared(q.get("d")) : null, badLink = !!q.get("d") && !shared;
  if (badLink) { $app.innerHTML = `<h2>🛡 ${esc(t("ciso.title"))}</h2><div class="card warn"><b>${esc(t("ciso.badlink"))}</b> <a href="#/ciso">${esc(t("ciso.mine"))}</a></div>`; return; }
  const  flags = shared ? shared.flags : review.flags, by = shared ? shared.by : review.by;
  const rows = [];
  for (const [key, f] of Object.entries(flags)) {
    const [pid, vid, pkg] = key.split("|"), at = pkg.lastIndexOf("@"), name = pkg.slice(0, at), ver = pkg.slice(at + 1);
    const facts = pid === "check" ? {sev: "unknown", cves: f.n ?? 0, exploited: false, known: false, pname: vid} : await factsFor(pid, vid, name, ver);
    rows.push({key, pid, vid, name, ver, ...f, steward: shared ? f.steward : (review.stewards[`${pid}|${name}`] || ""), ...facts});
  }
  rows.sort((a, b) => (b.exploited - a.exploited) || (SEV.indexOf(a.sev) < 0 ? 9 : SEV.indexOf(a.sev)) - (SEV.indexOf(b.sev) < 0 ? 9 : SEV.indexOf(b.sev)));
  const unowned = rows.filter(r => !r.steward).length, expl = rows.filter(r => r.exploited).length, crit = rows.filter(r => r.sev === "critical" || r.sev === "high").length;
  const today = new Date().toISOString().slice(0, 10);
  const table = rows.length ? `<div class="tablewrap"><table><thead><tr><th>${esc(t("comp.name"))}</th><th>${esc(t("ciso.product"))}</th><th>${esc(t("rev.reason"))}</th><th>${esc(t("ciso.risk"))}</th><th>${esc(t("rev.steward"))}</th><th>${esc(t("rev.note"))}</th><th>${esc(t("ciso.since"))}</th></tr></thead><tbody>${rows.map(r => `<tr>
    <td><b>${esc(r.name)}</b> <span class="muted">${esc(r.ver)}</span></td><td class="small">${r.known ? `<a href="${link(["p", r.pid, r.vid, "components"])}">${esc(r.pname)}</a>` : esc(r.pname || r.pid)}</td>
    <td><span class="badge">${esc(t("rev.reason." + r.reason))}</span></td>
    <td class="small">${r.known ? (r.sev === "none" ? esc(t("ciso.nocve")) : `${pill(r.sev)} ${esc(t("ciso.cves", {n: r.cves}))}`) : (r.pid === "check" ? esc(t("ciso.osvn", {n: r.cves})) : esc(t("ciso.unknownprod")))}${r.exploited ? ` <span class="badge no" style="white-space:nowrap">${esc(t("euvd.exploited"))}</span>` : ""}${r.euvd ? `<br><a class="badge" style="white-space:nowrap" href="https://euvd.enisa.europa.eu/vulnerability/${encodeURIComponent(r.euvd)}" target="_blank" rel="noopener">${esc(r.euvd)}</a>` : ""}</td>
    <td>${r.steward ? esc(r.steward) : `<span class="no">⚠ ${esc(t("rev.none"))}</span>`}</td><td class="small">${esc(r.note)}</td><td class="small">${esc(r.ts)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">${esc(t("ciso.empty"))}</p>`;
  $app.innerHTML = `<div class="ciso">
    <h2 style="margin-bottom:2px">🛡 ${esc(t("ciso.title"))}</h2><p class="small muted">${esc(t("ciso.lead"))} · ${esc(today)}${by ? ` · ${esc(t("ciso.by"))}: <b>${esc(by)}</b>` : ""}</p>
    ${shared ? `<div class="card warn"><b>${esc(t("ciso.shared"))}</b> <a href="#/ciso">${esc(t("ciso.mine"))}</a></div>` : ""}
    <div class="kpis"><div class="kpi"><span class="muted small">${esc(t("ciso.k.flagged"))}</span><b>${rows.length}</b></div><div class="kpi"><span class="muted small">${esc(t("ciso.k.exploited"))}</span><b class="${expl ? "no" : "ok"}">${expl}</b></div>
      <div class="kpi"><span class="muted small">${esc(t("ciso.k.crithigh"))}</span><b class="${crit ? "no" : "ok"}">${crit}</b></div><div class="kpi"><span class="muted small">${esc(t("ciso.k.unowned"))}</span><b class="${unowned ? "no" : "ok"}">${unowned}</b></div></div>
    <div class="card warn" style="margin-bottom:14px"><h3 style="margin:0 0 6px">🧭 ${esc(t("rev.stew.title"))}</h3><p class="small" style="margin:0">${esc(t("rev.stew.statement"))}</p></div>
    ${table}
    <div class="row noprint" style="margin-top:14px">${shared ? "" : `<label class="small">${esc(t("ciso.by"))} <input id="cisoBy" value="${esc(review.by)}" maxlength="80" style="width:12rem"></label>`}
      <button class="primary" id="cisoPrint" ${rows.length ? "" : "disabled"}>${esc(t("q.print"))}</button><button id="cisoCsv" ${rows.length ? "" : "disabled"}>CSV</button><button id="cisoJson" ${rows.length ? "" : "disabled"}>JSON</button>
      ${shared ? "" : `<button id="cisoLink" ${rows.length ? "" : "disabled"}>${esc(t("ciso.link"))}</button><button class="linkish no" id="cisoClear" ${rows.length ? "" : "disabled"}>${esc(t("ciso.clear"))}</button>`}<span id="cisoMsg" class="small ok"></span></div>
    <p class="small muted noprint">${esc(t("ciso.privacy"))}</p></div>`;
  const msg = x => { const m = document.getElementById("cisoMsg"); if (m) m.textContent = x; };
  document.getElementById("cisoPrint").onclick = () => window.print();
  document.getElementById("cisoCsv").onclick = () => downloadBlob(`ciso-review-${today}.csv`, [["package", "version", "product", "reason", "worst_severity", "cves", "exploited", "euvd", "steward", "note", "flagged"].map(csvCell).join(",")].concat(rows.map(r => [r.name, r.ver, r.pname || r.pid, r.reason, r.sev, r.cves, r.exploited, r.euvd, r.steward, r.note, r.ts].map(csvCell).join(","))).join("\n"), "text/csv");
  document.getElementById("cisoJson").onclick = () => downloadBlob(`ciso-review-${today}.json`, JSON.stringify({generated: today, prepared_by: by, flagged: rows.map(({key, known, ...r}) => r)}, null, 1));
  if (!shared) {
    document.getElementById("cisoBy").onchange = e => { review.by = e.target.value.trim(); saveReview(); };
    document.getElementById("cisoLink").onclick = async () => {
      const payload = b64enc({by: review.by, f: Object.entries(review.flags).map(([k, f]) => { const [pid, , pkg] = k.split("|"); return [k, f.reason, f.note, review.stewards[`${pid}|${pkg.slice(0, pkg.lastIndexOf("@"))}`] || "", f.ts, f.n]; })});
      const url = location.href.split("#")[0] + "#/ciso?d=" + payload;
      try { await navigator.clipboard.writeText(url); msg(t("q.copied") + (url.length > 1800 ? " · " + t("ciso.long") : "")); } catch (_) { prompt(t("ciso.link"), url); }
    };
    document.getElementById("cisoClear").onclick = () => { if (confirm(t("ciso.confirm"))) { review.flags = {}; saveReview(); cisoView(q); } };
  }
}

/* ---------- Quick check: drop an SBOM, nothing is uploaded; only package URLs go to OSV ---------- */
// purl types OSV.dev has advisories for; anything else (generic, deb, rpm, ...) cannot be judged by it and must not show a green "0"
const OSV_TYPES = new Set(["pypi", "npm", "maven", "golang", "cargo", "nuget", "gem", "composer", "hex", "pub", "cran", "swift"]);
function sbomPackages(doc) {
  const out = [];
  if (doc && doc.bomFormat === "CycloneDX") (function walk(cs) { (cs || []).forEach(c => { out.push({name: c.name || "?", version: c.version || "", purl: c.purl || ""}); walk(c.components); }); })(doc.components);
  else if (doc && Array.isArray(doc.packages)) doc.packages.forEach(p => out.push({name: p.name || "?", version: p.versionInfo || "", purl: ((p.externalRefs || []).find(r => r.referenceType === "purl") || {}).referenceLocator || ""}));
  else return null;
  const seen = new Set(); return out.filter(p => { const k = p.purl || p.name + "@" + p.version; return seen.has(k) ? false : (seen.add(k), true); });
}
async function osvBatch(purls, base) {
  const res = [];
  for (let i = 0; i < purls.length; i += 500) {
    const r = await fetch(base + "/v1/querybatch", {method: "POST", body: JSON.stringify({queries: purls.slice(i, i + 500).map(purl => ({package: {purl}}))}), signal: AbortSignal.timeout(30000)});
    if (!r.ok) throw new Error("HTTP " + r.status);
    res.push(...(await r.json()).results.map(x => (x.vulns || []).map(v => v.id)));
  }
  return res;
}
function checkView() {
  $crumb.textContent = t("chk.title");
  const osv = (userSetting("osvUrl") || SET_DEFAULTS.osvUrl).replace(/\/+$/, ""), host = (() => { try { return new URL(osv).host; } catch (_) { return osv; } })();
  $app.innerHTML = `<h2>⚡ ${esc(t("chk.title"))}</h2><p class="muted">${esc(t("chk.lead"))}</p>
    <div class="card"><div id="chkDrop" class="drop" tabindex="0" role="button" aria-label="${esc(t("chk.drop"))}">${esc(t("chk.drop"))}<input type="file" id="chkFile" accept=".json,application/json" hidden></div>
    <label class="blk" style="margin-top:10px">${esc(t("chk.paste"))}<textarea id="chkText" rows="4" spellcheck="false" style="width:100%;font-family:monospace"></textarea></label>
    <div class="row"><button class="primary" id="chkGo">${esc(t("chk.go"))}</button><a href="#/ciso" class="btn">🛡 ${esc(t("nav.ciso"))}</a><span id="chkMsg" class="small"></span></div>
    <p class="small muted">${esc(t("chk.privacy", {host}))}</p></div><div id="chkOut" style="margin-top:14px"></div>`;
  let fname = "pasted-sbom";
  const msg = (ok, x) => { const m = document.getElementById("chkMsg"); m.className = "small " + (ok ? "ok" : "no"); m.textContent = x; };
  const readFile = f => { fname = f.name.replace(/[^\w.-]/g, "_").slice(0, 60); const r = new FileReader(); r.onload = () => { document.getElementById("chkText").value = r.result; run(); }; r.readAsText(f); };
  const drop = document.getElementById("chkDrop"), file = document.getElementById("chkFile");
  drop.onclick = () => file.click(); drop.onkeydown = e => { if (e.key === "Enter" || e.key === " ") file.click(); };
  file.onchange = () => file.files[0] && readFile(file.files[0]);
  ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => e.dataTransfer.files[0] && readFile(e.dataTransfer.files[0]));
  document.getElementById("chkGo").onclick = run;
  async function run() {
    let doc; try { doc = JSON.parse(document.getElementById("chkText").value); } catch (_) { msg(false, t("chk.badjson")); return; }
    const pk = sbomPackages(doc); if (!pk) { msg(false, t("chk.badformat")); return; }
    const withPurl = pk.filter(p => OSV_TYPES.has((p.purl.match(/^pkg:([^/]+)\//) || [])[1])); msg(true, t("set.testing"));
    let res; try { res = await osvBatch(withPurl.map(p => p.purl), osv); } catch (e) { msg(false, `${t("set.fail")}: ${e.message}`); return; }
    const rows = withPurl.map((p, i) => ({...p, ids: res[i]})).sort((a, b) => b.ids.length - a.ids.length), vuln = rows.filter(r => r.ids.length).length;
    msg(true, t("chk.done", {n: pk.length, p: withPurl.length, v: vuln}));
    document.getElementById("chkOut").innerHTML = `<div class="tablewrap"><table><thead><tr><th>${esc(t("comp.name"))}</th><th>${esc(t("comp.version"))}</th><th>OSV</th><th>${esc(t("rev.flag"))}</th></tr></thead><tbody>${rows.map((r, i) => {
      const key = `check|${fname}|${r.name}@${r.version}`, f = review.flags[key];
      return `<tr><td>${esc(r.name)}</td><td>${esc(r.version)}</td><td class="${r.ids.length ? "no" : "ok"}">${r.ids.length ? esc(t("ciso.osvn", {n: r.ids.length})) + ` · <a class="small" href="https://osv.dev/vulnerability/${encodeURIComponent(r.ids[0])}" target="_blank" rel="noopener">${esc(r.ids[0])}</a>` : "✓ 0"}</td>
        <td><button class="flagbtn ${f ? "on" : ""}" data-i="${i}">⚑${f ? " " + esc(t("rev.reason." + f.reason)) : ""}</button></td></tr>`; }).join("")}${pk.length > withPurl.length ? `<tr><td colspan="4" class="small muted">${esc(t("chk.nopurl", {n: pk.length - withPurl.length}))}</td></tr>` : ""}</tbody></table></div>`;
    document.getElementById("chkOut").onclick = async e => {
      const b = e.target.closest(".flagbtn"); if (!b) return; const r = rows[b.dataset.i], key = `check|${fname}|${r.name}@${r.version}`, cur = review.flags[key];
      const x = await askModal({title: `⚑ ${r.name} ${r.version}`, fields: [{id: "reason", label: t("rev.reason"), options: reasonOpts(), value: cur?.reason || "defective"}, {id: "note", label: t("rev.note"), value: cur?.note || "", max: 300}], removeLabel: cur ? t("rev.flag_remove") : ""});
      if (!x) return; if (x._remove) delete review.flags[key]; else review.flags[key] = {reason: x.reason, note: x.note, ts: cur?.ts || new Date().toISOString().slice(0, 10), n: r.ids.length};
      saveReview(); b.className = "flagbtn" + (review.flags[key] ? " on" : ""); b.textContent = "⚑" + (review.flags[key] ? " " + t("rev.reason." + review.flags[key].reason) : "");
    };
  }
}

refreshCisoBtn();
