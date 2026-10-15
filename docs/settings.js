"use strict";
/* SBOM Explorer — Settings page (#/settings): API endpoints stored in localStorage ("sbom-settings"),
   read by extras.js (userSetting) at load. Loaded after extras.js. Shares its globals: $app, $crumb, esc, t. */

const SET_DEFAULTS = {osvUrl: "https://api.osv.dev", nvdUrl: "https://services.nvd.nist.gov/rest/json/cves/2.0"};
/* one entry per API: service id, settings key, i18n id, icon, tab, placeholder, optional (unconfigured = "not configured", not a failure) */
const SERVICES = [
  {id: "worker", key: "workerUrl", i18n: "worker", icon: "☁️", tab: "backend", ph: DEFAULT_WORKER_URL},
  {id: "apiBase", key: "apiBase", i18n: "apibase", icon: "🗄️", tab: "backend", ph: "https://sbom.example.com/", optional: true},
  {id: "osv", key: "osvUrl", i18n: "osv", icon: "🔎", tab: "databases", ph: SET_DEFAULTS.osvUrl},
  {id: "nvd", key: "nvdUrl", i18n: "nvd", icon: "🇺🇸", tab: "databases", ph: SET_DEFAULTS.nvdUrl},
  {id: "euvd", key: "euvdUrl", i18n: "euvd", icon: "🇪🇺", tab: "databases", ph: "https://sbom-explorer-upload.<you>.workers.dev/api/euvd", optional: true}];
let setDraft = null;  // unsaved edits, shared by the Backend/Databases tabs until Save/Reset reloads the page
const SET_TABS = ["status", "backend", "databases", "lookup"];
const TEST_CVE = "CVE-2021-44228";

const readSettings = () => { try { return JSON.parse(localStorage.getItem("sbom-settings") || "{}"); } catch (_) { return {}; } };
const writeSettings = o => { try { localStorage.setItem("sbom-settings", JSON.stringify(o)); return true; } catch (_) { return false; } };
const cleanUrl = u => (u || "").trim().replace(/\/+$/, "");
const isHttp = u => { try { return /^https?:$/.test(new URL(u).protocol); } catch (_) { return false; } };

/* one lookup per service: resolves {ok, found, detail} or throws (network/CORS/HTTP error) */
async function lookupService(name, cve, s) {
  const get = async url => { const r = await fetch(url, {cache: "no-store", signal: AbortSignal.timeout(8000)}); if (r.status === 404) return null; if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); };
  if (name === "worker") { const j = await get(cleanUrl(s.workerUrl || DEFAULT_WORKER_URL) + "/api/health"); return {found: !!j, detail: j?.mode ? "mode " + j.mode : ""}; }
  if (name === "apiBase") { const j = await get(cleanUrl(s.apiBase) + "/api/health"); return {found: !!j && !!j.api, detail: ""}; }
  if (name === "osv") { const j = await get(cleanUrl(s.osvUrl || SET_DEFAULTS.osvUrl) + "/v1/vulns/" + encodeURIComponent(cve)); return {found: !!j, detail: j?.id || ""}; }
  if (name === "nvd") {
    const j = await get((s.nvdUrl || SET_DEFAULTS.nvdUrl) + "?cveId=" + encodeURIComponent(cve));
    const c = j?.vulnerabilities?.[0]?.cve; if (!c) return {found: false, detail: ""};
    const m = c.metrics || {}, k = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"].find(x => m[x]);
    return {found: true, detail: k ? t("set.score", {s: m[k][0].cvssData.baseScore}) : ""};
  }
  if (name === "euvd") {
    const base = cleanUrl(s.euvdUrl); const j = await get(base + (base.includes("?") ? "&" : "?") + "text=" + encodeURIComponent(cve) + "&size=5");
    const i = (j?.items || []).find(x => (x.aliases || "").split(/\s+/).includes(cve)); if (!i) return {found: false, detail: ""};
    return {found: true, detail: [i.id, i.baseScore ? t("set.score", {s: i.baseScore}) : "", i.exploitedSince ? t("set.exploited") : ""].filter(Boolean).join(" · ")};
  }
}

function settingsView(tab) {
  tab = SET_TABS.includes(tab) ? tab : "status";
  $crumb.textContent = t("set.title");
  const draft = setDraft || (setDraft = readSettings()), status = {};  // draft survives tab switches (each tab is a route); status[id] = {state: chk|ok|fail|off, text}
  const svcUrl = sv => draft[sv.key] || (sv.optional ? "" : sv.ph);
  const hostOf = u => { try { return new URL(u).host; } catch (_) { return u; } };
  const setState = (id, state, text) => { status[id] = {state, text}; paintStatus(); };

  async function check(sv) {
    const d = {...draft};
    if (sv.optional && !d[sv.key]) { setState(sv.id, "off", t("set.notset")); return; }
    if (d[sv.key] && !isHttp(d[sv.key])) { setState(sv.id, "fail", "http(s) URL"); return; }
    setState(sv.id, "chk", t("set.testing")); const t0 = performance.now();
    try { const r = await lookupService(sv.id, TEST_CVE, d), ms = Math.round(performance.now() - t0);
      setState(sv.id, r.found ? "ok" : "fail", `${r.found ? t("set.connected") : t("set.notfound")} · ${ms} ms${r.detail ? " · " + r.detail : ""}`); }
    catch (e) { setState(sv.id, "fail", `${t("set.fail")}: ${e.name === "TimeoutError" ? "timeout" : e.message}`); }
  }
  const checkAll = () => Promise.all(SERVICES.map(check));

  function paintStatus() {
    $app.querySelectorAll("[data-st]").forEach(el => { const s = status[el.dataset.st]; if (s) { el.className = "svc-state " + s.state; el.textContent = s.text; } });
    $app.querySelectorAll("[data-card]").forEach(el => { const s = status[el.dataset.card]; if (s) el.dataset.state = s.state; });
    const sum = document.getElementById("setSummary"); if (!sum) return;
    const active = SERVICES.filter(sv => (status[sv.id] || {}).state !== "off"), okN = active.filter(sv => (status[sv.id] || {}).state === "ok").length;
    const pending = active.some(sv => !status[sv.id] || status[sv.id].state === "chk");
    sum.className = "svc-sum " + (pending ? "chk" : okN === active.length ? "ok" : "fail");
    sum.textContent = pending ? t("set.testing") : t("set.summary", {n: okN, m: active.length});
  }
  const card = (sv, edit) => `<div class="svc" data-card="${sv.id}" data-state="${edit && !status[sv.id] ? "idle" : (status[sv.id] || {state: "chk"}).state}"><div class="svc-h"><span class="svc-ic" aria-hidden="true">${sv.icon}</span><b>${esc(t("set." + sv.i18n))}</b>${sv.optional ? `<span class="badge">${esc(t("set.optional"))}</span>` : ""}</div>
    ${edit ? `<input data-k="${sv.key}" type="url" value="${esc(draft[sv.key] || "")}" placeholder="${esc(sv.ph)}" autocomplete="off" spellcheck="false" aria-label="${esc(t("set." + sv.i18n))}">
      <p class="small muted">${esc(t("set." + sv.i18n + "_h"))}</p>
      <div class="row"><button type="button" data-test="${sv.id}">${esc(t("set.test"))}</button><span class="svc-state idle" data-st="${sv.id}" aria-live="polite"></span></div>`
    : `<code class="small">${esc(hostOf(svcUrl(sv)) || "—")}</code><div class="svc-state chk" data-st="${sv.id}" aria-live="polite"></div>
      <a class="small" href="#/settings/${sv.tab}">${esc(t("set.configure"))} →</a>`}</div>`;

  const panes = {
    status: () => `<div class="row" style="justify-content:space-between;margin-bottom:10px"><span id="setSummary" class="svc-sum chk"></span><button id="setRefresh">↻ ${esc(t("set.refresh"))}</button></div>
      <div class="grid svc-grid">${SERVICES.map(sv => card(sv, false)).join("")}</div><p class="small muted" style="margin-top:14px">${esc(t("set.privacy"))}</p>`,
    backend: () => `<p class="muted">${esc(t("set.backend_h"))}</p><div class="grid svc-grid">${SERVICES.filter(sv => sv.tab === "backend").map(sv => card(sv, true)).join("")}</div>`,
    databases: () => `<p class="muted">${esc(t("set.vuln_h"))}</p><div class="grid svc-grid">${SERVICES.filter(sv => sv.tab === "databases").map(sv => card(sv, true)).join("")}</div>`,
    lookup: () => `<div class="card"><h3>${esc(t("set.lookup"))}</h3><p class="small muted">${esc(t("set.lookup_h"))}</p>
      <form id="lkForm" class="row" style="gap:8px"><input id="lkCve" value="${TEST_CVE}" pattern="CVE-\\d{4}-\\d{4,}" required style="flex:1;min-width:0" aria-label="CVE"><button class="primary" type="submit">${esc(t("set.lookup_go"))}</button></form>
      <div id="lkOut" class="small" style="margin-top:10px"></div></div>`};

  $app.innerHTML = `<h2>⚙ ${esc(t("set.title"))}</h2><p class="muted">${esc(t("set.lead"))}</p>
    <nav class="tabs" aria-label="${esc(t("set.title"))}">${SET_TABS.map(k => `<a href="#/settings/${k}" class="${k === tab ? "on" : ""}">${esc(t("set.tab." + k))}</a>`).join("")}</nav>
    ${panes[tab]()}
    ${tab === "backend" || tab === "databases" ? `<div class="savebar"><button class="primary" id="setSave">${esc(t("set.save"))}</button><button id="setReset">${esc(t("set.reset"))}</button><span id="setMsg" class="small"></span></div>` : ""}`;

  $app.querySelectorAll("input[data-k]").forEach(i => i.oninput = () => { const v = i.value.trim(); if (v) draft[i.dataset.k] = v; else delete draft[i.dataset.k]; });
  $app.querySelectorAll("[data-test]").forEach(b => b.onclick = () => check(SERVICES.find(sv => sv.id === b.dataset.test)));
  const rf = document.getElementById("setRefresh"); if (rf) rf.onclick = checkAll;
  const msg = (ok, text) => { const m = document.getElementById("setMsg"); if (m) { m.className = "small " + (ok ? "ok" : "no"); m.textContent = text; } };
  const save = document.getElementById("setSave");
  if (save) save.onclick = () => {
    const bad = Object.entries(draft).find(([, v]) => !isHttp(v));
    if (bad) { msg(false, `${t("set.fail")}: ${bad[0]} — http(s) URL`); return; }
    if (!writeSettings(draft)) { msg(false, t("set.fail") + ": localStorage"); return; }
    msg(true, t("set.saved")); setTimeout(() => location.reload(), 500);
  };
  const rs = document.getElementById("setReset"); if (rs) rs.onclick = () => { try { localStorage.removeItem("sbom-settings"); } catch (_) {} location.reload(); };
  const lk = document.getElementById("lkForm");
  if (lk) lk.onsubmit = async e => {
    e.preventDefault(); const cve = document.getElementById("lkCve").value.trim().toUpperCase(), out = document.getElementById("lkOut");
    const names = ["osv", "nvd", "euvd"];
    out.innerHTML = names.map(n => `<div class="row" style="gap:10px"><b style="min-width:3.5rem">${n.toUpperCase()}</b><span class="svc-state chk" data-lk="${n}">${esc(t("set.testing"))}</span></div>`).join("");
    await Promise.all(names.map(async n => { const el = out.querySelector(`[data-lk="${n}"]`), set = (ok, x) => { el.className = "svc-state " + ok; el.textContent = x; };
      if (n === "euvd" && !draft.euvdUrl) { set("off", t("set.notset")); return; }
      const t0 = performance.now();
      try { const r = await lookupService(n, cve, draft); set(r.found ? "ok" : "fail", `${r.found ? t("set.found") : t("set.notfound")} · ${Math.round(performance.now() - t0)} ms${r.detail ? " · " + r.detail : ""}`); }
      catch (err) { set("fail", `${t("set.fail")}: ${err.message}`); } }));
  };
  if (tab === "status") checkAll();
}
