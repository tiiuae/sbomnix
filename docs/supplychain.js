"use strict";
/* SBOM Explorer — supply chain view: multi-tier dependency graph and supplier map.
   Pure functions first (node-exportable), browser UI below. Data: variant.graph {root, edges: [[from, to]]} (from -1 = the product itself)
   and component rows [name, version, eco, type, licence, class, cve state, key, supplier]. A tier is the dependency depth:
   tier 1 = what the product uses directly, tier 2 = what those use, and so on. */

const SC_MAX_PER_TIER = 40, SC_MAX_EDGES_NODES = 200;
const SC_SEV = ["critical", "high", "medium", "low"];

/* Depth of every component from the product. Without edges there is no tiering to show: everything is one flat tier.
   Components no edge reaches are returned as `unlinked` (listed, never silently dropped). */
function scTiers(count, graph) {
  const edges = (graph && graph.edges) || [], adj = new Map();
  edges.forEach(([a, b]) => { if (!adj.has(a)) adj.set(a, []); adj.get(a).push(b); });
  if (!edges.length) return {tiers: count ? [[...Array(count).keys()]] : [], unlinked: [], hasEdges: false, depth: Array(count).fill(1)};
  const depth = Array(count).fill(0), queue = [-1];
  let head = 0;
  while (head < queue.length) {
    const n = queue[head++], d = n === -1 ? 0 : depth[n];
    for (const m of adj.get(n) || []) if (m >= 0 && m < count && depth[m] === 0) { depth[m] = d + 1; queue.push(m); }
  }
  const tiers = [], unlinked = [];
  depth.forEach((d, i) => { if (d === 0) unlinked.push(i); else (tiers[d - 1] = tiers[d - 1] || []).push(i); });
  return {tiers: tiers.map(t => t || []), unlinked, hasEdges: true, depth};
}

/* risk facts per component row: worst severity, KEV, CVE count, licence class (from the variant data) */
function scFacts(v, rows) {
  const last = v.history[v.history.length - 1], byLabel = new Map();
  (last.cve_pairs || []).forEach(([cve, , , label]) => {
    if (!byLabel.has(label)) byLabel.set(label, new Set());
    byLabel.get(label).add(cve);
  });
  return rows.map(r => {
    const ids = [...(byLabel.get(`${r.name}@${r.version}`) || [])];
    let worst = "", kev = false;
    ids.forEach(id => {
      const d = (v.vuln_defs || {})[id] || {};
      if (d.kev) kev = true;
      const s = SC_SEV.indexOf(d.sev);
      if (s >= 0 && (worst === "" || s < SC_SEV.indexOf(worst))) worst = d.sev;
    });
    const checked = r.status === "osv" || r.status === "nvd";
    return {cves: ids.length, worst, kev, state: kev ? "kev" : worst || (ids.length ? "unknown" : checked ? "clean" : "unchecked")};
  });
}

/* suppliers: who supplies how many components, their worst risk, and which other suppliers they depend on */
function scSuppliers(rows, facts, graph) {
  const map = new Map(), key = r => r.supplier || "";
  rows.forEach((r, i) => {
    const k = key(r);
    if (!map.has(k)) map.set(k, {name: k, idx: [], kev: 0, worst: "", dependsOn: new Map()});
    const s = map.get(k); s.idx.push(i);
    if (facts[i].kev) s.kev++;
    const w = SC_SEV.indexOf(facts[i].worst);
    if (w >= 0 && (s.worst === "" || w < SC_SEV.indexOf(s.worst))) s.worst = facts[i].worst;
  });
  ((graph && graph.edges) || []).forEach(([a, b]) => {
    if (a < 0 || !rows[a] || !rows[b]) return;
    const from = map.get(key(rows[a])), to = key(rows[b]);
    if (from && to !== key(rows[a])) from.dependsOn.set(to, (from.dependsOn.get(to) || 0) + 1);
  });
  return [...map.values()].sort((x, y) => (x.name === "") - (y.name === "") || y.idx.length - x.idx.length);
}

if (typeof module !== "undefined" && module.exports) module.exports = {scTiers, scFacts, scSuppliers, SC_MAX_PER_TIER};

/* ---------- browser UI: product tab "Supply chain" ---------- */
const SC_FILL = {kev: "var(--crit)", critical: "var(--crit)", high: "var(--high)", medium: "var(--med)", low: "var(--low)", unknown: "var(--unk)", clean: "var(--good)", unchecked: "var(--unk)"};
const SC_TEXT = {medium: "#222"};

function supplyChainTab() {
  return `<p class="muted">${esc(t("sc.lead"))}</p><div id="scBody"><p class="muted">${esc(t("set.testing"))}</p></div>`;
}
async function wireSupplyChain(v) {
  const body = document.getElementById("scBody"); if (!body) return;
  if (typeof licensesReady !== "undefined") await licensesReady;
  const rows = (typeof LIC_TABLE !== "undefined" && LIC_TABLE ? licenseRows(v, LIC_TABLE) : v.components.map((c, i) => ({i, name: c[0], version: c[1], cls: c[5], status: c[6], license: c[4] || "", key: c[7] || ""})))
    .map((r, i) => ({...r, supplier: (v.components[i] || [])[8] || ""}));
  const graph = v.graph || {root: "", edges: []}, tiers = scTiers(rows.length, graph), facts = scFacts(v, rows), sup = scSuppliers(rows, facts, graph);
  const flat = !tiers.hasEdges, noSup = rows.filter(r => !r.supplier).length, noSupplierData = rows.length > 0 && noSup === rows.length;
  const stateCount = k => facts.filter(f => f.state === k).length, label = n => (n === -1 ? graph.root || t("sc.product") : `${rows[n].name} ${rows[n].version}`.trim());
  const cut = (s0, n) => (s0.length > n ? s0.slice(0, n - 1) + "…" : s0);
  const STATES = ["kev", "critical", "high", "medium", "low", "unknown", "clean", "unchecked"];
  const legend = STATES.filter(k => stateCount(k)).map(k => `<span class="small" style="margin-right:12px"><span style="display:inline-block;width:.8em;height:.8em;border-radius:3px;background:${SC_FILL[k]};vertical-align:middle"></span> ${esc(t("sc.state." + k))} <b>${stateCount(k)}</b></span>`).join("");
  const kpi = (lab, val, cls = "") => `<div class="kpi"><span class="muted small">${esc(lab)}</span><b class="${cls}">${val}</b></div>`;
  const kpis = `<div class="kpis">${kpi(t("sc.k.components"), rows.length)}${kpi(t("sc.k.tiers"), flat ? "—" : tiers.tiers.length)}
    ${noSupplierData ? kpi(t("sc.k.suppliers"), "—") : kpi(t("sc.k.suppliers"), sup.filter(s0 => s0.name).length) + kpi(t("sc.k.nosupplier"), noSup, noSup ? "no" : "ok")}${kpi(t("sc.k.kev"), stateCount("kev"), stateCount("kev") ? "no" : "ok")}</div>`;

  /* flat SBOM: no tiers to draw, so show every component grouped by risk instead of a meaningless column of boxes */
  const chip = n => `<button type="button" class="scchip" data-n="${n}" style="border-left-color:${SC_FILL[facts[n].state]}" title="${esc(label(n))}">${esc(cut(label(n), 34))}${facts[n].kev ? " ⚑" : ""}</button>`;
  const grouped = () => {
    const bar = rows.length ? `<div class="bar" role="img" aria-label="${esc(t("sc.by_risk"))}">${STATES.filter(k => stateCount(k)).map(k => `<span style="width:${100 * stateCount(k) / rows.length}%;background:${SC_FILL[k]}" title="${esc(t("sc.state." + k))}: ${stateCount(k)}"></span>`).join("")}</div>` : "";
    return `<div class="card"><h3 style="margin:0 0 6px">${esc(t("sc.by_risk"))}</h3><p class="small muted" style="margin:0 0 8px">${esc(t("sc.by_risk_h"))}</p>${bar}<div style="margin:8px 0">${legend}</div>
      ${STATES.filter(k => stateCount(k)).map(k => { const idx = rows.map((_, i) => i).filter(i => facts[i].state === k);
        return `<details ${k === "kev" || k === "critical" || (idx.length <= 24 && k !== "unchecked") ? "open" : ""} style="margin:6px 0"><summary><b>${esc(t("sc.state." + k))}</b> <span class="muted small">${idx.length}</span></summary><div style="margin-top:6px">${idx.slice(0, 80).map(chip).join("")}${idx.length > 80 ? `<span class="small muted"> ${esc(t("sc.more_chips", {n: idx.length - 80}))}</span>` : ""}</div></details>`; }).join("")}
      <div id="scDetail" class="small" style="margin-top:8px" aria-live="polite"></div></div>`;
  };

  /* with dependency data: tiered graph, tiers as columns */
  const NW = 168, NH = 26, GX = 56, GY = 8, PAD = 16;
  const graphCard = () => {
    const cols = [[-1], ...tiers.tiers.map(t0 => t0.slice(0, SC_MAX_PER_TIER))], pos = new Map();
    cols.forEach((col, c) => col.forEach((n, k) => pos.set(n, {x: PAD + c * (NW + GX), y: PAD + k * (NH + GY)})));
    const height = PAD * 2 + Math.max(...cols.map(c => c.length)) * (NH + GY) - GY, width = PAD * 2 + cols.length * (NW + GX) - GX;
    const drawEdges = rows.length <= SC_MAX_EDGES_NODES;
    const edgeSvg = drawEdges ? (graph.edges || []).filter(([a, b]) => pos.has(a) && pos.has(b)).map(([a, b]) => { const p = pos.get(a), q = pos.get(b), x1 = p.x + NW, y1 = p.y + NH / 2, x2 = q.x, y2 = q.y + NH / 2, mx = (x1 + x2) / 2; return `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" fill="none" stroke="var(--muted)" stroke-opacity=".45" stroke-width="1.2"/>`; }).join("") : "";
    const nodeSvg = cols.flatMap((col, c) => col.map(n => {
      const p = pos.get(n), f = n === -1 ? null : facts[n], fill = n === -1 ? "var(--brand)" : SC_FILL[f.state], tx = n === -1 ? "var(--brand-ink)" : SC_TEXT[f.state] || "#fff";
      return `<g class="scnode" data-n="${n}" tabindex="0" role="button" aria-label="${esc(label(n))}" style="cursor:pointer"><rect x="${p.x}" y="${p.y}" width="${NW}" height="${NH}" rx="7" style="fill:${fill}"/><text x="${p.x + 8}" y="${p.y + 17}" font-size="12" style="fill:${tx}">${esc(cut(label(n), 24))}${f && f.kev ? " ⚑" : ""}</text></g>`; })).join("");
    const heads = cols.map((col, c) => `<text x="${PAD + c * (NW + GX)}" y="11" font-size="11" style="fill:var(--muted)">${c === 0 ? "" : esc(t("sc.tier", {n: c}))}</text>`).join("");
    const more = tiers.tiers.map((t0, i) => t0.length > SC_MAX_PER_TIER ? `<li>${esc(t("sc.more", {n: t0.length - SC_MAX_PER_TIER, tier: i + 1}))}</li>` : "").join("");
    return `<div class="card"><h3 style="margin:0 0 6px">${esc(t("sc.graph"))}</h3><p class="small muted" style="margin:0 0 8px">${esc(t("sc.graph_h"))}</p><div>${legend}</div>
      <div class="scwrap"><svg id="scSvg" width="${width}" height="${height + 14}" viewBox="0 -14 ${width} ${height + 14}" role="img" aria-label="${esc(t("sc.graph"))}">${heads}${edgeSvg}${nodeSvg}</svg></div>
      ${drawEdges ? "" : `<p class="small muted">${esc(t("sc.noedges_big", {n: SC_MAX_EDGES_NODES}))}</p>`}${more ? `<ul class="small muted">${more}</ul>` : ""}<div id="scDetail" class="small" style="margin-top:8px" aria-live="polite"></div></div>`;
  };

  const supplierSection = () => noSupplierData
    ? `<div class="card" style="margin-top:14px"><h3 style="margin:0 0 6px">${esc(t("sc.suppliers"))}</h3><p class="small muted" style="margin:0">${esc(t("sc.no_supplier_data"))}</p></div>`
    : `<h3 style="margin-top:14px">${esc(t("sc.suppliers"))}</h3><p class="small muted">${esc(t("sc.suppliers_h"))}</p>
      <div class="tablewrap"><table><thead><tr><th>${esc(t("sc.supplier"))}</th><th>${esc(t("cmp2.components"))}</th><th>${esc(t("ciso.risk"))}</th><th>${esc(t("sc.dependson"))}</th><th>${esc(t("cmp.package"))}</th></tr></thead><tbody>${sup.slice(0, 200).map(s0 => {
        const dep = [...s0.dependsOn].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([n]) => n || t("sc.nosupplier")).join(", ");
        return `<tr><td>${s0.name ? esc(s0.name) : `<span class="no">⚠ ${esc(t("sc.nosupplier"))}</span>`}</td><td>${s0.idx.length}</td><td class="small">${s0.worst ? `<span class="pill s-${s0.worst}">${esc(s0.worst)}</span>` : "—"}${s0.kev ? ` <span class="badge no">KEV ×${s0.kev}</span>` : ""}</td><td class="small">${esc(dep || "—")}</td><td class="small">${esc(s0.idx.slice(0, 4).map(i => rows[i].name).join(", "))}${s0.idx.length > 4 ? " …" : ""}</td></tr>`; }).join("")}</tbody></table></div>`;

  body.innerHTML = kpis + (flat ? `<p class="small muted" style="margin:0 0 10px">ℹ️ ${esc(t("sc.noedges"))}</p>${grouped()}` : graphCard()) +
    (tiers.unlinked.length ? `<p class="small muted">${esc(t("sc.unlinked", {n: tiers.unlinked.length}))}: ${esc(tiers.unlinked.slice(0, 12).map(i => rows[i].name).join(", "))}${tiers.unlinked.length > 12 ? " …" : ""}</p>` : "") + supplierSection();

  const detail = document.getElementById("scDetail"), show = n => {
    if (!detail) return;
    if (n === -1) { detail.textContent = t("sc.product_d", {n: (graph.edges || []).filter(e => e[0] === -1).length}); return; }
    const r = rows[n], f = facts[n], up = (graph.edges || []).filter(e => e[1] === n).map(e => e[0] === -1 ? (graph.root || t("sc.product")) : rows[e[0]].name), down = (graph.edges || []).filter(e => e[0] === n).map(e => rows[e[1]].name);
    detail.innerHTML = `<b>${esc(r.name)} ${esc(r.version)}</b> · ${esc(t("sc.supplier"))}: ${r.supplier ? esc(r.supplier) : `<span class="muted">${esc(t("sc.nosupplier"))}</span>`} · ${esc(t("comp.licence"))}: ${esc(r.license || "—")} (${esc(t("lic." + r.cls))}) · ${esc(t("sc.state." + f.state))}${f.cves ? ` · ${f.cves} CVE` : ""}${flat ? "" : `<br>${esc(t("sc.usedby"))}: ${esc(up.join(", ") || "—")} · ${esc(t("sc.uses"))}: ${esc(down.join(", ") || "—")}`}`;
  };
  body.querySelectorAll(".scnode, .scchip").forEach(g => { g.onclick = () => show(+g.dataset.n); g.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); show(+g.dataset.n); } }; });
}
