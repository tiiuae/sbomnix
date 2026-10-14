"use strict";
/* SBOM Explorer — SBOM quality (sbomqs-style): tab, overview card, compliance checklists, exports, capabilities table.
   Loaded after extras.js. Data: variant.quality (latest release, full) and history[].quality (compact). */

const Q_CATS = ["identification", "provenance", "integrity", "completeness", "licensing", "vulnerability", "structural", "sharing"];
const GRADE_COLOR = {A: "var(--good)", B: "#74b816", C: "var(--med)", D: "var(--high)", E: "#e8590c", F: "var(--crit)"};
const PROFILE_ORDER = ["ntia", "bsi", "fsct"];
const scoreColor = s => s >= 8 ? "var(--good)" : s >= 6 ? "var(--med)" : s >= 4 ? "var(--high)" : "var(--crit)";
const gradeChip = (g, extra = "") => `<span class="grade" style="background:${GRADE_COLOR[g] || "var(--unk)"}" title="${esc(t("q.chip"))}">${esc(g)}${extra}</span>`;
const stPill = st => `<span class="pill" style="background:${st === "compliant" ? "var(--good)" : st === "partial" ? "var(--med);color:#222" : "var(--crit)"}">${esc(t("q.st." + st))}</span>`;

function qBars(cats) {
  return Q_CATS.filter(c => cats[c] != null).map(c => {
    const v = typeof cats[c] === "number" ? cats[c] : cats[c].score;
    return `<div style="margin:8px 0"><div class="row" style="justify-content:space-between"><span>${esc(t("qc." + c))}</span><b>${v.toFixed(1)}</b></div><div class="bar"><span style="width:${v * 10}%;background:${scoreColor(v)}"></span></div></div>`;
  }).join("");
}
const weakest = (q, n = 3) => q.features.filter(f => !f.na && f.score < 10).sort((a, b) => a.score - b.score).slice(0, n);

/* ---------- overview card ---------- */
function qualityCard(p, pid, vid, v) {
  const q = v.quality;
  if (!q) return "";
  return `<div class="card" style="margin-top:14px" data-tour="qual"><div class="row" style="justify-content:space-between"><h3 style="margin:0">${esc(t("q.card"))}</h3>${gradeChip(q.grade, " " + q.score.toFixed(1))}</div>
    <div class="row" style="margin:8px 0">${PROFILE_ORDER.map(k => `<span class="small">${esc(t("qp." + k))} ${stPill(q.profiles[k].status)}</span>`).join(" &nbsp; ")}</div>
    <div class="small muted">${esc(t("q.card_weak"))}</div>
    ${weakest(q).map(f => `<div class="row small" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:4px 0"><span>${esc(t("qf." + f.id))}</span><b style="color:${scoreColor(f.score)}">${f.score.toFixed(1)}</b></div>`).join("")}
    <a href="${link(["p", pid, vid, "quality"])}">${esc(t("q.open"))}</a></div>`;
}

/* ---------- quality tab ---------- */
function qualityTab(p, v) {
  const q = v.quality, h = v.history;
  if (!q) return `<p class="muted">${esc(t("av.nodata"))}</p>`;
  const catOpts = `<option value="">${esc(t("q.all"))}</option>` + Q_CATS.filter(c => q.cats[c]).map(c => `<option value="${c}">${esc(t("qc." + c))}</option>`).join("");
  const missKeys = Object.keys(q.missing).filter(k => FEATURE_LEVEL(q, k) === "comp");
  const profile = k => {
    const pr = q.profiles[k];
    const reqs = pr.reqs.map(r => `<div class="row small" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:4px 0"><span class="${r.ok ? "ok" : r.pct ? "" : "no"}">${r.ok ? "✔" : "✖"} ${esc(t("qr." + r.id))}${r.note ? ` <span class="muted">— ${esc(r.note)}</span>` : ""}</span><span class="muted">${esc(t("q.req." + r.level))} · ${r.pct}%</span></div>`).join("");
    return `<div class="card"><div class="row" style="justify-content:space-between"><h3 style="margin:0">${esc(t("qp." + k))}</h3>${stPill(pr.status)}</div>${pr.approximate ? `<p class="small muted">${esc(t("q.approx"))}</p>` : ""}${reqs}</div>`;
  };
  const trend = h.length > 1 && h.every(x => x.quality) ? `<div class="card" style="margin-top:14px"><h3>${esc(t("q.trend"))}</h3>${lineChart(h.map(x => x.version), [{name: t("q.score"), color: "var(--brand)", vals: h.map(x => x.quality.score)}], {yTitle: t("q.trend"), zero: false})}</div>` : "";
  const struct = q.structural.problems.length || q.structural.missing_fields.length
    ? `<ul class="small">${[...q.structural.missing_fields, ...q.structural.problems].slice(0, 20).map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : `<p class="small ok">${esc(t("q.structural_ok"))}</p>`;
  const official = v.quality_official ? `<div class="card" style="margin-top:14px"><h3>${esc(t("q.official"))}</h3><p class="small muted">${esc(t("q.official_d"))}</p><pre class="small" style="overflow:auto;max-height:260px">${esc(JSON.stringify(v.quality_official, null, 1))}</pre></div>` : "";
  const badge = `badges/${p.id}-${Object.keys(p.variants).find(k => p.variants[k] === v)}.svg`;
  return `<p class="muted">${esc(t("q.lead"))}</p>
  <div class="card"><div class="row" style="justify-content:space-between;align-items:center"><div><span class="muted small">${esc(t("q.title"))}</span><div style="font-size:3rem;font-weight:800;line-height:1.1">${q.score.toFixed(1)}<span class="muted" style="font-size:1.1rem">/10</span></div></div>${gradeChip(q.grade)}</div>
   <div class="small muted">${esc(q.format)} ${esc(q.spec)} · ${q.components} ${esc(t("kpi.components").toLowerCase())} · ${esc(t("q.licsrc", {src: q.licence_source}))}</div>${qBars(q.cats)}</div>
  <h3 style="margin-top:18px">${esc(t("q.profiles"))}</h3><div class="grid">${PROFILE_ORDER.map(profile).join("")}</div>
  ${trend}
  <div class="card" style="margin-top:14px"><div class="row" style="justify-content:space-between"><h3 style="margin:0">${esc(t("q.features"))}</h3><select id="qCat">${catOpts}</select></div><p class="small muted">${esc(t("q.na_note"))}</p>
   <div class="tablewrap"><table><thead><tr><th>${esc(t("q.col.check"))}</th><th>${esc(t("q.col.score"))}</th><th>${esc(t("q.col.pass"))}</th><th>${esc(t("q.col.impact"))}</th></tr></thead><tbody id="qRows"></tbody></table></div></div>
  <div class="card" style="margin-top:14px"><h3>${esc(t("q.missing"))}</h3>
   <label class="blk">${esc(t("q.missing_pick"))}<select id="qMiss">${missKeys.map(k => `<option value="${k}">${esc(t("qf." + k))}</option>`).join("")}</select></label><div id="qMissOut" class="small" style="margin-top:8px"></div></div>
  <div class="card" style="margin-top:14px"><h3>${esc(t("q.structural"))}</h3>${struct}</div>${official}
  <div class="card" style="margin-top:14px"><h3>${esc(t("q.share"))}</h3><div class="row"><button id="qJson">${esc(t("q.export.json"))}</button><button id="qHtml">${esc(t("q.export.html"))}</button><button id="qCsv">${esc(t("q.export.csv"))}</button><button id="qLink">${esc(t("q.link"))}</button></div>
   <div class="row" style="margin-top:10px"><img src="${esc(badge)}" alt="SBOM quality badge" height="20"><code class="small">![SBOM quality](${esc(badge)})</code></div><p class="small muted">${esc(t("q.badge_md"))}</p></div>`;
}
function FEATURE_LEVEL(q, id) { const f = q.features.find(x => x.id === id); return f ? f.level : ""; }

function wireQuality(p, vid, v) {
  const q = v.quality; if (!q) return;
  const rows = document.getElementById("qRows"), cat = document.getElementById("qCat");
  const draw = () => {
    rows.innerHTML = q.features.filter(f => !cat.value || f.cat === cat.value).map(f => f.na
      ? `<tr class="muted"><td>${esc(t("qf." + f.id))}<br><code>${esc(f.id)}</code></td><td colspan="2">${esc(t("q.na"))}</td><td>${esc(t("qi." + f.impact))}</td></tr>`
      : `<tr><td>${esc(t("qf." + f.id))}<br><code>${esc(f.id)}</code></td><td style="min-width:110px"><b style="color:${scoreColor(f.score)}">${f.score.toFixed(1)}</b><div class="bar"><span style="width:${f.score * 10}%;background:${scoreColor(f.score)}"></span></div></td><td>${f.pass}/${f.total}</td><td class="small">${esc(t("qi." + f.impact))}</td></tr>`).join("");
  };
  cat.onchange = draw; draw();
  const miss = document.getElementById("qMiss"), out = document.getElementById("qMissOut");
  const drawMiss = () => {
    const m = q.missing[miss.value];
    if (!m) { out.innerHTML = `<span class="ok">${esc(t("q.missing_none"))}</span>`; return; }
    const shown = m.items.slice(0, 60);
    out.innerHTML = `<b>${esc(t("q.missing_n", {n: m.n}))}</b> <span class="muted">(${esc(t("q.missing_first", {n: shown.length}))})</span><div style="margin-top:6px">${shown.map(x => `<code>${esc(x)}</code>`).join(" · ")}</div>`;
  };
  if (miss) { miss.onchange = drawMiss; drawMiss(); }
  const ver = lastOf(v).version, base = `${p.id}-${vid}-${ver}`;
  document.getElementById("qJson").onclick = () => downloadBlob(`${base}.quality.json`, JSON.stringify({product: p.id, variant: vid, version: ver, ...q}, null, 1));
  document.getElementById("qCsv").onclick = () => {
    const csv = ["feature,category,impact,component"];
    for (const [fid, m] of Object.entries(q.missing)) { const f = q.features.find(x => x.id === fid); if (f?.level === "comp") m.items.forEach(c => csv.push([fid, f.cat, f.impact, c].map(x => `"${String(x).replace(/"/g, '""')}"`).join(","))); }
    downloadBlob(`${base}.quality-findings.csv`, csv.join("\n"), "text/csv");
  };
  document.getElementById("qHtml").onclick = () => downloadBlob(`${base}.quality-report.html`, qualityReportHtml(p, v, vid), "text/html");
  document.getElementById("qLink").onclick = async e => { try { await navigator.clipboard.writeText(location.href.split("#")[0] + link(["p", p.id, vid, "quality"])); e.target.textContent = t("q.copied"); } catch (_) { /* clipboard blocked */ } };
}

/* ---------- standalone HTML report (no external assets; follows the current language) ---------- */
function qualityReportHtml(p, v, vid) {
  const q = v.quality, h = lastOf(v);
  const row = (a, b, c) => `<tr><td>${a}</td><td>${b}</td><td>${c}</td></tr>`;
  const cats = Q_CATS.filter(c => q.cats[c]).map(c => row(esc(t("qc." + c)), q.cats[c].score.toFixed(1), "")).join("");
  const feats = q.features.map(f => row(esc(t("qf." + f.id)) + `<br><small>${esc(f.id)}</small>`, f.na ? esc(t("q.na")) : f.score.toFixed(1), f.na ? "" : `${f.pass}/${f.total}`)).join("");
  const profs = PROFILE_ORDER.map(k => `<h3>${esc(t("qp." + k))} — ${esc(t("q.st." + q.profiles[k].status))}${q.profiles[k].approximate ? ` <small>(${esc(t("q.approx"))})</small>` : ""}</h3><ul>${q.profiles[k].reqs.map(r => `<li>${r.ok ? "✔" : "✖"} ${esc(t("qr." + r.id))} — ${r.pct}%</li>`).join("")}</ul>`).join("");
  return `<!doctype html><html lang="${LANG}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(t("report.title"))} — ${esc(p.name)} ${esc(h.version)}</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:24px auto;padding:0 16px;color:#14181f}h1{margin-bottom:0}.score{font-size:3rem;font-weight:800}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:6px;text-align:left}small{color:#667}@media print{body{margin:0}}</style></head><body>
<h1>${esc(t("report.title"))}</h1><p>${esc(p.name)} · ${esc(v.label)} ${esc(h.version)} · ${esc(h.date)}</p>
<div class="score">${q.score.toFixed(1)}/10 · ${esc(q.grade)}</div><p><small>${esc(q.format)} ${esc(q.spec)} · ${q.components} ${esc(t("kpi.components").toLowerCase())}</small></p>
<h2>${esc(t("q.cats"))}</h2><table>${cats}</table><h2>${esc(t("q.profiles"))}</h2>${profs}<h2>${esc(t("q.features"))}</h2><table>${feats}</table>
<p><small>${esc(t("report.generated"))}: ${new Date().toISOString().slice(0, 10)} · ${esc(t("report.disclaimer"))}</small></p></body></html>`;
}

/* ---------- About: what this tool covers vs sbomqs / Interlynk ---------- */
const CAPS = [["score", "sbomqs", "have"], ["cats", "sbomqs", "have"], ["missing", "sbomqs", "have"], ["ntia", "sbomqs", "have"], ["bsi", "sbomqs", "partial"], ["fsct", "sbomqs", "partial"],
  ["oct", "sbomqs", "no"], ["json", "sbomqs", "have"], ["weights", "sbomqs", "have"], ["share", "sbomqs", "partial"], ["airgap", "sbomqs", "have"], ["dtrack", "sbomqs", "no"],
  ["ingest", "Interlynk", "partial"], ["doctor", "Interlynk", "no"], ["supplier", "Interlynk", "have"], ["qcsv", "Interlynk", "have"], ["vuln", "Interlynk", "have"],
  ["vex", "Interlynk", "partial"], ["policy", "Interlynk", "partial"], ["integrations", "Interlynk", "no"], ["portfolio", "Interlynk", "have"], ["compliance", "Interlynk", "partial"]];
function capabilitiesCard() {
  const col = {have: "var(--good)", partial: "var(--med)", no: "var(--unk)"};
  return `<div class="card" style="margin-top:14px"><h3>${esc(t("cap.title"))}</h3><p class="small muted">${esc(t("cap.lead"))}</p><div class="tablewrap"><table><tbody>${CAPS.map(([id, src, st]) =>
    `<tr><td><span class="badge">${esc(src)}</span></td><td>${esc(t(`cap.${id}.t`))}<br><span class="small muted">${esc(t(`cap.${id}.n`))}</span></td><td><span class="pill" style="background:${col[st]}${st === "partial" ? ";color:#222" : ""}">${esc(t("cap.st." + st))}</span></td></tr>`).join("")}</tbody></table></div></div>`;
}
