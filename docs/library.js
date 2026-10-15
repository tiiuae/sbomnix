"use strict";
/* SBOM Explorer — library: import CycloneDX / SPDX JSON, keep your own and third-party SBOMs in one place (browser, IndexedDB),
   check them for vulnerabilities (OSV, CISA KEV, EPSS, public PoCs) and keep them current.
   Pure functions first (node-exportable, the network is injected so tests can mock it), browser storage and page below.
   An imported SBOM becomes an Explorer product with the same shape sbomnix --explorer-dir writes, so every tab works on it.
   Honesty rules: a component that was not looked up stays "pending" / "none", never "clean"; an ecosystem OSV does not cover is
   "unmatched"; PoC data not collected is absent (the UI shows "?"), not 0. */

if (typeof module !== "undefined" && typeof licenseClass === "undefined") Object.assign(globalThis, require("./compliance.js"));  // node: the browser has these as globals

const LIB_MAX_COMPONENTS = 20000, LIB_MAX_BYTES = 25 * 1024 * 1024, LIB_MAX_VULN_IDS = 300, LIB_POC_MAX = 80, LIB_BATCH = 500, LIB_CONCURRENCY = 6;
const LIB_OSV_TYPE_LIST = ["pypi", "npm", "maven", "golang", "cargo", "nuget", "gem", "composer", "hex", "pub", "cran", "swift"];
const LIB_SEVERITIES = ["critical", "high", "medium", "low", "unknown"];
const LIB_DQ = ["osv", "nvd", "pending", "unmatched", "none"];
const libPurlType = purl => ((String(purl || "").match(/^pkg:([^/]+)\//) || [])[1] || "other").toLowerCase();

/* ---------- parsing ---------- */
const libCdxLicense = c => (Array.isArray(c.licenses) ? c.licenses : []).map(l => (l && (l.expression || (l.license && (l.license.id || l.license.name)))) || "").filter(x => typeof x === "string" && x).join(" AND ");
const libSpdxLicense = p => [p.licenseDeclared, p.licenseConcluded].find(x => typeof x === "string" && x && !["NOASSERTION", "NONE"].includes(x)) || "";
const libSpdxSupplier = s => (!s || String(s).toUpperCase() === "NOASSERTION" ? "" : String(s).replace(/^(Organization|Person):\s*/i, "").trim());
const libSummary = doc => Object.fromEntries(Object.entries(doc).map(([k, v]) => [k, Array.isArray(v) ? `${v.length} items` : v && typeof v === "object" ? "object" : v]));

/* text or object -> {format, spec, serial, timestamp, tools, name, version, subject, components[], edges[[from,to]], topLevel, hasMeta ...}; throws Error with a message fit for the user */
function libNormalize(input) {
  let doc = input;
  if (typeof input === "string") {
    const s = input.trim();
    if (!s) throw new Error("the file is empty");
    if (input.length > LIB_MAX_BYTES) throw new Error("the file is too large (limit 25 MB)");
    if (s.startsWith("<")) throw new Error("XML is not supported: export the SBOM as CycloneDX JSON or SPDX JSON");
    if (/^SPDXVersion:/m.test(s.slice(0, 200))) throw new Error("SPDX tag-value is not supported: export the SBOM as SPDX JSON");
    try { doc = JSON.parse(s); } catch (_) { throw new Error("the file is not valid JSON"); }
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new Error("not a CycloneDX or SPDX JSON document");
  if (doc.bomFormat === "CycloneDX") return libNormalizeCdx(doc);
  if (typeof doc.spdxVersion === "string" && doc.spdxVersion.startsWith("SPDX-") && Array.isArray(doc.packages)) return libNormalizeSpdx(doc);
  throw new Error("not a CycloneDX or SPDX JSON document");
}

function libNormalizeCdx(doc) {
  const comps = [], refs = new Map(), edges = [], meta = doc.metadata || {}, root = meta.component || {};
  (function walk(list, parent) {
    (Array.isArray(list) ? list : []).forEach(c => {
      if (!c || typeof c !== "object") return;
      if (comps.length >= LIB_MAX_COMPONENTS) throw new Error(`too many components (limit ${LIB_MAX_COMPONENTS})`);
      const i = comps.length, sup = c.supplier && typeof c.supplier === "object" ? c.supplier.name : "";
      comps.push({name: String(c.name || "?"), version: String(c.version || ""), type: String(c.type || "library"), purl: typeof c.purl === "string" ? c.purl : "", cpe: typeof c.cpe === "string" ? c.cpe : "",
        license: libCdxLicense(c), supplier: String(sup || c.publisher || c.author || "").trim(), hashes: Array.isArray(c.hashes) && c.hashes.length > 0, raw: c});
      if (c["bom-ref"]) refs.set(c["bom-ref"], i);
      if (parent >= 0) edges.push([parent, i]);
      walk(c.components, i);
    });
  })(doc.components, -1);
  if (root["bom-ref"]) refs.set(root["bom-ref"], -1);
  const seen = new Set(edges.map(e => e.join(",")));
  (Array.isArray(doc.dependencies) ? doc.dependencies : []).forEach(d => {
    const a = refs.get(d && d.ref); if (a === undefined) return;
    (Array.isArray(d.dependsOn) ? d.dependsOn : []).forEach(r => { const b = refs.get(r); if (b !== undefined && b !== a && !seen.has(a + "," + b)) { seen.add(a + "," + b); edges.push([a, b]); } });
  });
  const types = {}; comps.forEach(c => { const k = c.type.toUpperCase(); types[k] = (types[k] || 0) + 1; });
  return {format: "CycloneDX", spec: `CycloneDX-${doc.specVersion || "?"}`, serial: doc.serialNumber || null, docVersion: doc.version ?? null, timestamp: meta.timestamp || "", tools: Array.isArray(meta.tools) ? meta.tools : [],
    name: String(root.name || ""), version: String(root.version || ""), subject: {type: String(root.type || "").toUpperCase(), name: root.name || null, version: root.version || null, purl: root.purl || ""},
    components: comps, edges, componentTypes: types, topLevel: libSummary(doc), hasAuthor: !!((meta.authors && meta.authors.length) || (meta.tools && (Array.isArray(meta.tools) ? meta.tools.length : Object.keys(meta.tools).length)) || meta.manufacture),
    hasDependencies: Array.isArray(doc.dependencies) && doc.dependencies.length > 0};
}

function libNormalizeSpdx(doc) {
  const pkgs = doc.packages, byId = new Map(pkgs.map((p, i) => [p && p.SPDXID, i]));
  let rootId = (Array.isArray(doc.documentDescribes) && doc.documentDescribes[0]) || null;
  const rels = Array.isArray(doc.relationships) ? doc.relationships : [];
  if (!rootId) { const d = rels.find(r => r && r.relationshipType === "DESCRIBES" && r.spdxElementId === "SPDXRef-DOCUMENT"); rootId = d ? d.relatedSpdxElement : null; }
  const rootPkg = rootId && byId.has(rootId) ? pkgs[byId.get(rootId)] : null;
  const comps = [], idx = new Map();
  pkgs.forEach(p => {
    if (!p || typeof p !== "object" || p.SPDXID === rootId) return;
    if (comps.length >= LIB_MAX_COMPONENTS) throw new Error(`too many components (limit ${LIB_MAX_COMPONENTS})`);
    const refs = (Array.isArray(p.externalRefs) ? p.externalRefs : []).filter(r => r && typeof r === "object"), purl = String((refs.find(r => r.referenceType === "purl") || {}).referenceLocator || ""), cpe = String((refs.find(r => r.referenceType === "cpe23Type") || {}).referenceLocator || "");
    idx.set(p.SPDXID, comps.length);
    comps.push({name: String(p.name || "?"), version: String(p.versionInfo || ""), type: String(p.primaryPackagePurpose || "library"), purl, cpe, license: libSpdxLicense(p), supplier: libSpdxSupplier(p.supplier), hashes: Array.isArray(p.checksums) && p.checksums.length > 0, raw: p});
  });
  const at = id => (id === rootId ? -1 : idx.has(id) ? idx.get(id) : undefined), edges = [], seen = new Set();
  const add = (a, b) => { if (a !== undefined && b !== undefined && a !== b && !seen.has(a + "," + b)) { seen.add(a + "," + b); edges.push([a, b]); } };
  rels.forEach(r => {
    if (!r) return;
    const a = at(r.spdxElementId), b = at(r.relatedSpdxElement);
    if (r.relationshipType === "DEPENDS_ON" || r.relationshipType === "CONTAINS") add(a, b);
    else if (r.relationshipType === "DEPENDENCY_OF" || r.relationshipType === "CONTAINED_BY") add(b, a);   // "A DEPENDENCY_OF B": B depends on A
  });
  const types = {}; comps.forEach(c => { const k = c.type.toUpperCase(); types[k] = (types[k] || 0) + 1; });
  const ci = doc.creationInfo || {};
  return {format: "SPDX", spec: doc.spdxVersion, serial: doc.documentNamespace || null, docVersion: null, timestamp: ci.created || "", tools: (ci.creators || []).map(c => ({name: c})),
    name: String((rootPkg && rootPkg.name) || doc.name || ""), version: String((rootPkg && rootPkg.versionInfo) || ""), subject: {type: rootPkg ? String(rootPkg.primaryPackagePurpose || "").toUpperCase() : "", name: (rootPkg && rootPkg.name) || doc.name || null, version: (rootPkg && rootPkg.versionInfo) || null, purl: ""},
    components: comps, edges, componentTypes: types, topLevel: libSummary(doc), hasAuthor: !!(ci.creators && ci.creators.length), hasDependencies: edges.length > 0};
}

/* ---------- building the product ---------- */
const libSlug = s => (String(s || "sbom").toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^[^a-z0-9]+|[-.]+$/g, "").slice(0, 40) || "sbom");

function libMaturity(norm, rows, method) {
  const cs = norm.components, pct = f => Math.round(100 * cs.filter(f).length / Math.max(1, cs.length));
  const cov = {purl: pct(c => c.purl), version: pct(c => c.version), license: pct(c => c.license), supplier: pct(c => c.supplier), hash: pct(c => c.hashes), cve: Math.round(100 * rows.filter(r => r[6] === "osv" || r[6] === "nvd").length / Math.max(1, rows.length))};
  const ntia = {"Supplier name": cov.supplier === 100, "Component name": cs.every(c => c.name && c.name !== "?"), "Component version": cov.version === 100, "Other unique identifiers (purl)": cov.purl === 100,
    "Dependency relationships": !!norm.hasDependencies, "Author of SBOM data": !!norm.hasAuthor, "Timestamp": !!norm.timestamp};
  const dims = {"Inventory completeness": Math.round((cov.purl + cov.version) / 2), "NTIA minimum elements": Math.round(100 * Object.values(ntia).filter(Boolean).length / Object.keys(ntia).length), "License compliance": cov.license, "Integrity & provenance": cov.hash};
  const w = method.weights, score = Math.round(Object.keys(dims).reduce((s, k) => s + dims[k] * w[k], 0) / Object.keys(dims).reduce((s, k) => s + w[k], 0));
  const lv = method.levels.find(l => score < l.below) || method.levels[method.levels.length - 1];
  return {score, level: lv.level, level_name: lv.name, dims, ntia, coverage: cov};
}

/* the manifest entry of a product; also used after every update so the home page never disagrees with the product */
function libBrief(product) {
  const vid = Object.keys(product.variants)[0], v = product.variants[vid], e = v.history[v.history.length - 1];
  const b = {id: product.id, type: product.type, icon: product.icon, demo: !!product.demo, name: product.name, tagline: product.tagline, local: true, origin: product.origin || "own",
    variants: {[vid]: {label: v.label, version: e.version, date: e.date, components: e.components, vulns: e.vulns, cve_checked: (e.dq.osv || 0) + (e.dq.nvd || 0), dq: e.dq, maturity: v.maturity.score, level: v.maturity.level, level_name: v.maturity.level_name, releases: 1, gaps: 0}}};
  return b;
}

/* opts: {id, name?, variant?, method (manifest.method), table (licenses.json), today?, origin?, sourceLabel?, srcName?} -> {product, brief} */
function libBuildProduct(norm, opts) {
  const {id, method, table} = opts, variant = opts.variant || "imported", today = opts.today || new Date().toISOString().slice(0, 10), name = (opts.name || norm.name || id).trim();
  const rows = norm.components.map(c => {
    const key = c.cpe || c.purl || "";
    return [c.name, c.version, libPurlType(c.purl), "LIBRARY", c.license, table ? licenseClass(c.license, table) : (c.license ? "other" : "unknown"), key ? "pending" : "none", key, c.supplier, c.purl];
  });
  const mat = libMaturity(norm, rows, method), dq = Object.fromEntries(LIB_DQ.map(k => [k, rows.filter(r => r[6] === k).length]));
  const eco = {}, lic = {}; rows.forEach(r => { eco[r[2]] = (eco[r[2]] || 0) + 1; lic[r[5]] = (lic[r[5]] || 0) + 1; });
  const entry = {version: norm.version || "unknown", date: today, components: rows.length, eco, licenses: lic, vulns: Object.fromEntries(LIB_SEVERITIES.map(k => [k, 0])), vuln_total: 0, vulns_open: Object.fromEntries(LIB_SEVERITIES.map(k => [k, 0])), open_total: 0, dq,
    cve_pairs: [], diff: {added: [], removed: [], changed: []}, diff_counts: {added: 0, removed: 0, changed: 0}, maturity: {score: mat.score, level: mat.level}, files: []};
  const sample = norm.components.length ? JSON.stringify(norm.components[0].raw).slice(0, 4000) : "{}";
  let sampleObj; try { sampleObj = JSON.parse(sample); } catch (_) { sampleObj = {note: "sample too large to show"}; }
  const origin = opts.origin === "third-party" ? "third-party" : "own";
  const v = {label: opts.label || variant.charAt(0).toUpperCase() + variant.slice(1), history: [entry], vuln_defs: {}, components: rows, maturity: mat, sbom: {file: opts.srcName || "imported.json", format: norm.format, spec: norm.spec, serial: norm.serial, doc_version: norm.docVersion, timestamp: norm.timestamp,
      tools: norm.tools, subject: norm.subject, top_level: norm.topLevel, component_types: norm.componentTypes, properties: {purl: norm.components.filter(c => c.purl).length, cpe: norm.components.filter(c => c.cpe).length}, samples: {generic: sampleObj}},
    graph: {root: norm.name, edges: norm.edges}, file_path: opts.srcName || "imported.json", upgrades: [], process_actions: [], data_gaps: [], data_sources: {}};
  const label = opts.sourceLabel ? String(opts.sourceLabel).slice(0, 80) : "";
  const product = {id, type: "software", icon: origin === "third-party" ? "📥" : "📦", demo: false, repo: null, name, origin, source_label: label, imported: today, local: true,
    tagline: {en: origin === "third-party" ? `Third-party ${norm.format} SBOM${label ? " from " + label : ""}` : `Imported ${norm.format} SBOM`, pl: origin === "third-party" ? `SBOM ${norm.format} firmy trzeciej${label ? ": " + label : ""}` : `Zaimportowany SBOM ${norm.format}`},
    description: {en: "", pl: ""}, website: "", links: [], contact: {}, repo_flags: {}, evidence_files: [], compliance: null, variants: {[variant]: v}};
  return {product, brief: libBrief(product)};
}

/* ---------- CVSS v3 base score and OSV severity ---------- */
const CVSS3_W = {AV: {N: 0.85, A: 0.62, L: 0.55, P: 0.2}, AC: {L: 0.77, H: 0.44}, UI: {N: 0.85, R: 0.62}, CIA: {H: 0.56, L: 0.22, N: 0}, PR_U: {N: 0.85, L: 0.62, H: 0.27}, PR_C: {N: 0.85, L: 0.68, H: 0.5}};
const cvssRoundup = x => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
/* "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" -> {score, severity} or null when the vector is not a complete v3 base vector */
function libCvss3(vector) {
  const m = /^CVSS:3\.[01]\/(.+)$/.exec(String(vector || "")); if (!m) return null;
  const t = Object.fromEntries(m[1].split("/").map(p => p.split(":")));
  const ok = (k, set) => Object.prototype.hasOwnProperty.call(set, t[k]);
  if (!ok("AV", CVSS3_W.AV) || !ok("AC", CVSS3_W.AC) || !ok("UI", CVSS3_W.UI) || !ok("C", CVSS3_W.CIA) || !ok("I", CVSS3_W.CIA) || !ok("A", CVSS3_W.CIA) || !["U", "C"].includes(t.S)) return null;
  const changed = t.S === "C", pr = (changed ? CVSS3_W.PR_C : CVSS3_W.PR_U)[t.PR]; if (pr === undefined) return null;
  const iss = 1 - (1 - CVSS3_W.CIA[t.C]) * (1 - CVSS3_W.CIA[t.I]) * (1 - CVSS3_W.CIA[t.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss, expl = 8.22 * CVSS3_W.AV[t.AV] * CVSS3_W.AC[t.AC] * pr * CVSS3_W.UI[t.UI];
  const score = impact <= 0 ? 0 : cvssRoundup(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
  return {score, severity: score === 0 ? "unknown" : score < 4 ? "low" : score < 7 ? "medium" : score < 9 ? "high" : "critical"};
}
/* OSV record -> {sev, score, vector}: the CVSS v3 vector when there is one, else the database's own severity word, else unknown */
function libOsvSeverity(rec) {
  for (const s of (rec && rec.severity) || []) { const r = s && s.type === "CVSS_V3" ? libCvss3(s.score) : null; if (r) return {sev: r.severity, score: r.score, vector: s.score}; }
  const w = String((rec && rec.database_specific && rec.database_specific.severity) || "").toUpperCase();
  return {sev: {CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low"}[w] || "unknown", score: null, vector: null};
}

/* ---------- vulnerability check (network injected) ---------- */
const libPool = async (items, n, fn) => { const out = new Array(items.length); let next = 0; await Promise.all(Array.from({length: Math.min(n, items.length)}, async () => { while (next < items.length) { const i = next++; out[i] = await fn(items[i], i); } })); return out; };
const libCve = id => /^CVE-\d{4}-\d{4,}$/i.test(id);

/* Look every component with a supported purl up in OSV, then add KEV, EPSS and public PoC data. deps: {fetch, osv, kevUrl, epssUrl, pocBase, today?, onProgress?}.
   OSV, KEV and EPSS must all succeed (else it throws and the caller keeps the old data: a product with half-checked data would read as safer than it is).
   PoC data is best effort: a CVE whose PoC lookup failed simply has no `poc` key. Returns {product, brief, stats}; the input is not modified. */
async function libEnrich(product, deps) {
  const p = structuredClone(product), vid = Object.keys(p.variants)[0], v = p.variants[vid], rows = v.components, today = deps.today || new Date().toISOString().slice(0, 10), say = deps.onProgress || (() => {});
  const getJson = async (url, init, what) => {
    let res; try { res = await deps.fetch(url, init); } catch (e) { throw new Error(`${what}: network error (${e.message || e})`); }
    if (!res.ok) { const err = new Error(`${what}: HTTP ${res.status}`); err.status = res.status; throw err; }
    return res.json();
  };
  const osvTypes = new Set(LIB_OSV_TYPE_LIST);
  const purls = [...new Set(rows.map(r => r[9]).filter(x => x && osvTypes.has(libPurlType(x))))];
  rows.forEach(r => { r[6] = !r[7] ? "none" : r[9] && osvTypes.has(libPurlType(r[9])) ? "osv" : r[9] ? "unmatched" : "pending"; });   // looked up / ecosystem not covered / only a CPE (not queried here) / nothing to look up

  say("osv");
  const idsByPurl = new Map();
  for (let i = 0; i < purls.length; i += LIB_BATCH) {
    const chunk = purls.slice(i, i + LIB_BATCH), d = await getJson(`${deps.osv}/v1/querybatch`, {method: "POST", body: JSON.stringify({queries: chunk.map(purl => ({package: {purl}}))})}, "OSV");
    if (!d || !Array.isArray(d.results) || d.results.length !== chunk.length) throw new Error("OSV: unexpected answer");
    d.results.forEach((r, j) => idsByPurl.set(chunk[j], ((r && r.vulns) || []).map(x => x.id)));
  }
  const allIds = [...new Set([...idsByPurl.values()].flat())], truncated = allIds.length > LIB_MAX_VULN_IDS, ids = allIds.slice(0, LIB_MAX_VULN_IDS);
  say("details");
  const recs = await libPool(ids, LIB_CONCURRENCY, async id => { try { return await getJson(`${deps.osv}/v1/vulns/${encodeURIComponent(id)}`, undefined, "OSV " + id); } catch (e) { if (e.status === 404) return null; throw e; } });
  const keyOf = new Map(), defs = {};
  ids.forEach((id, i) => {
    const rec = recs[i]; if (!rec) return;
    const cve = (rec.aliases || []).find(libCve) || (libCve(id) ? id : null), key = cve ? cve.toUpperCase() : id;   // CVE id when there is one: KEV, EPSS and PoC data are keyed by it
    keyOf.set(id, key);
    if (defs[key]) { (defs[key].osv_ids = defs[key].osv_ids || [defs[key].osv]).push(id); return; }
    const sev = libOsvSeverity(rec), text = rec.summary || String(rec.details || "").split("\n").find(l => l.trim() && !l.startsWith("#")) || "";
    defs[key] = {id: key, src: "osv", osv: id, alias: key !== id ? id : null, sev: sev.sev, score: sev.score, vector: sev.vector, summary: String(text).slice(0, 400), published: String(rec.published || "").slice(0, 10) || null, kev: false, kev_src: [], kev_info: null, epss: null};
  });
  const missingDetails = ids.filter((id, i) => !recs[i]).length;

  say("kev");
  const kevDoc = await getJson(deps.kevUrl, undefined, "CISA KEV"), kev = new Map(((kevDoc && kevDoc.vulnerabilities) || []).map(x => [x.cveID, {date: x.dateAdded || null, ransomware: x.knownRansomwareCampaignUse === "Known"}]));
  if (!kev.size) throw new Error("CISA KEV: unexpected answer");
  const cves = Object.keys(defs).filter(libCve);
  cves.forEach(c => { if (kev.has(c)) { defs[c].kev = true; defs[c].kev_src = ["cisa"]; defs[c].kev_info = kev.get(c); } });

  say("epss");
  for (let i = 0; i < cves.length; i += 50) {
    const d = await getJson(`${deps.epssUrl}?cve=${cves.slice(i, i + 50).join(",")}`, undefined, "EPSS");
    ((d && d.data) || []).forEach(x => { if (defs[x.cve]) defs[x.cve].epss = Number(x.epss); });
  }

  say("poc");
  const byRisk = [...cves].sort((a, b) => (defs[b].kev - defs[a].kev) || ((defs[b].epss || 0) - (defs[a].epss || 0))).slice(0, LIB_POC_MAX);
  await libPool(byRisk, LIB_CONCURRENCY, async c => {
    try { const d = await getJson(`${deps.pocBase}/${c.split("-")[1]}/${c}.json`, undefined, "PoC " + c); defs[c].poc = Array.isArray(d) && d.length ? {n: d.length, url: d[0].html_url || ""} : null; }
    catch (e) { if (e.status === 404) defs[c].poc = null; }   // 404 = no repository named after this CVE; any other failure leaves the key absent
  });

  const pairs = [];
  rows.forEach(r => { if (r[9] && idsByPurl.has(r[9])) idsByPurl.get(r[9]).forEach(id => { if (keyOf.has(id)) pairs.push([keyOf.get(id), r[7], "", `${r[0]}@${r[1]}`]); }); });
  const counts = Object.fromEntries(LIB_SEVERITIES.map(k => [k, 0])); Object.values(defs).forEach(d => { counts[d.sev] += 1; });
  const e = v.history[v.history.length - 1];
  e.cve_pairs = pairs; e.vulns = counts; e.vulns_open = {...counts}; e.vuln_total = Object.keys(defs).length; e.open_total = e.vuln_total; e.dq = Object.fromEntries(LIB_DQ.map(k => [k, rows.filter(r => r[6] === k).length]));
  v.vuln_defs = defs; v.maturity.coverage.cve = Math.round(100 * rows.filter(r => r[6] === "osv" || r[6] === "nvd").length / Math.max(1, rows.length));
  v.data_sources = {osv_asof: today, kev_day: today, epss_asof: today, poc_asof: today};
  v.data_gaps = [...(truncated ? [{id: "truncated", n: allIds.length - ids.length}] : []), ...(missingDetails ? [{id: "missing_details", n: missingDetails}] : [])];
  p.checked = today;
  return {product: p, brief: libBrief(p), stats: {cves: e.vuln_total, kev: Object.values(defs).filter(d => d.kev).length, checked_components: e.dq.osv, unmatched: e.dq.unmatched, truncated: allIds.length - ids.length, missing_details: missingDetails, poc_checked: byRisk.length}};
}

/* days since the oldest data source of a variant; null when the variant records none */
function libAgeDays(v, now = Date.now()) {
  const days = Object.entries(v.data_sources || {}).filter(([k, d]) => /_asof$|_day$/.test(k) && /^\d{4}-\d{2}-\d{2}/.test(String(d))).map(([, d]) => Math.floor((now - Date.parse(String(d).slice(0, 10))) / 864e5));
  return days.length ? Math.max(...days) : null;
}

/* ---------- browser: the library in IndexedDB, and the Library page (#/library) ---------- */
const LIB_DB = "sbom-explorer-library", LIB_STORE = "sboms", LIB_SETTINGS = "sbom-library-settings";
const LIB_URLS = {kev: "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json", epss: "https://api.first.org/data/v1/epss", poc: "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master", osv: "https://api.osv.dev"};
const libAvailable = typeof indexedDB !== "undefined";
let libDbPromise = null;
const libDb = () => libDbPromise || (libDbPromise = new Promise((res, rej) => {
  const r = indexedDB.open(LIB_DB, 1);
  r.onupgradeneeded = () => r.result.createObjectStore(LIB_STORE, {keyPath: "id"});
  r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); r.onblocked = () => rej(new Error("storage is blocked"));
}));
const libTx = async (mode, fn) => { const db = await libDb(); return new Promise((res, rej) => { const tx = db.transaction(LIB_STORE, mode); const r = fn(tx.objectStore(LIB_STORE)); tx.oncomplete = () => res(r && r.result); tx.onerror = () => rej(tx.error); tx.onabort = () => rej(tx.error || new Error("storage aborted")); }); };
const libAll = async () => { if (!libAvailable) return []; try { return (await libTx("readonly", st => st.getAll())) || []; } catch (e) { console.warn("library unavailable:", e); return []; } };
const libGetRecord = id => libTx("readonly", st => st.get(id));
const libPutRecord = rec => libTx("readwrite", st => st.put(rec));
const libDeleteRecord = id => libTx("readwrite", st => st.delete(id));

const libSettings = () => { try { return {auto: true, days: 7, ...JSON.parse(localStorage.getItem(LIB_SETTINGS) || "{}")}; } catch (_) { return {auto: true, days: 7}; } };
const libSaveSettings = o => { try { localStorage.setItem(LIB_SETTINGS, JSON.stringify(o)); } catch (_) { /* storage blocked: lasts until reload */ } };
const libIsStale = (r, days) => !r.checkedAt || Date.now() - Date.parse(r.checkedAt) > days * 864e5;

/* imported products are listed next to the built-in ones */
async function libMergeManifest() {
  const recs = await libAll();
  manifest.products = manifest.products.filter(p => !p.local).concat(recs.map(r => r.brief));
  recs.forEach(r => { delete cache[r.id]; });
  return recs;
}
const libChanged = () => libMergeManifest();

async function libImportText(text, srcName, opts = {}) {
  if (!libAvailable) throw new Error(t("lib.nostorage"));
  await licensesReady;
  if (typeof LIC_TABLE === "undefined" || !LIC_TABLE) throw new Error(t("cmp2.nolic"));
  const norm = libNormalize(text), existing = new Set((await libAll()).map(r => r.id));
  const name = (opts.name || norm.name || String(srcName || "").replace(/\.[^.]+$/, "") || "SBOM").trim().slice(0, 80), base = "local-" + libSlug(name);
  let id = base; for (let n = 2; existing.has(id); n++) id = `${base}-${n}`;
  const origin = opts.origin === "third-party" ? "third-party" : "own", {product, brief} = libBuildProduct(norm, {id, name, variant: "imported", method: manifest.method, table: LIC_TABLE, origin, sourceLabel: opts.sourceLabel || "", srcName: String(srcName || "sbom.json").slice(0, 120)});
  const rec = {id, brief, product, source: text, srcName: product.variants.imported.sbom.file, importedAt: new Date().toISOString(), checkedAt: null, origin, sourceLabel: product.source_label, lastError: "", lastTry: ""};
  await libPutRecord(rec);
  try { if (navigator.storage && navigator.storage.persist) navigator.storage.persist(); } catch (_) { /* best effort */ }
  await libChanged();
  return rec;
}

/* look the SBOM up (OSV, KEV, EPSS, PoC). A failure keeps the previous data and records why. */
async function libCheck(id, onProgress) {
  const rec = await libGetRecord(id); if (!rec) throw new Error("not in your library");
  const osv = (typeof userSetting === "function" && userSetting("osvUrl") || LIB_URLS.osv).replace(/\/+$/, "");
  const deps = {fetch: (u, i) => fetch(u, {...(i || {}), signal: AbortSignal.timeout(45000)}), osv, kevUrl: LIB_URLS.kev, epssUrl: LIB_URLS.epss, pocBase: LIB_URLS.poc, onProgress};
  const now = new Date().toISOString();
  try {
    const res = await libEnrich(rec.product, deps);
    Object.assign(rec, {product: res.product, brief: res.brief, checkedAt: now, lastTry: now, lastError: ""});
    await libPutRecord(rec); await libChanged();
    return res.stats;
  } catch (e) {
    rec.lastError = String(e && e.message || e); rec.lastTry = now; await libPutRecord(rec);
    throw e;
  }
}

/* auto-update: on load, re-check library entries that were checked before and are now older than the chosen age.
   Entries never checked are not touched (no lookups without the user's say-so); a failed entry is not retried for an hour. */
async function libAutoRefresh() {
  const st = libSettings(); if (!st.auto || !libAvailable) return 0;
  const due = (await libAll()).filter(r => r.checkedAt && libIsStale(r, st.days) && !(r.lastTry && Date.now() - Date.parse(r.lastTry) < 36e5));
  let n = 0;
  for (const r of due) { try { await libCheck(r.id); n++; } catch (e) { console.warn("auto-update failed for", r.id, e.message); } }
  return n;
}

/* notes on the product page: data that is old, or a local SBOM that was never checked */
function libNote(p, v) {
  const days = libSettings().days;
  if (p.local && !p.checked) return `<div class="card warn small">${esc(t("lib.unchecked_note"))} <a href="#/library">${esc(t("lib.title"))}</a></div>`;
  const age = libAgeDays(v), limit = p.local ? days : 14;
  return age !== null && age >= limit ? `<div class="card warn small">⏰ ${esc(t("lib.stale_note", {n: age}))}${p.local ? ` <a href="#/library">${esc(t("lib.title"))}</a>` : ""}</div>` : "";
}
/* the SBOM tab of an imported product downloads the file that was imported */
async function libWireSbom(p) {
  const go = document.getElementById("sbGo"), nm = document.getElementById("sbName"), ver = document.getElementById("sbVer");
  const r = go && await libGetRecord(p.id).catch(() => null); if (!r) return;
  go.href = URL.createObjectURL(new Blob([r.source], {type: "application/json"})); go.download = r.srcName || "sbom.json"; go.removeAttribute("target"); go.style.display = "";
  if (nm) nm.textContent = r.srcName; if (ver) ver.disabled = true;
}

async function libraryView() {
  $crumb.textContent = t("lib.title");
  const st = libSettings(), recs = (await libMergeManifest()).sort((a, b) => b.importedAt.localeCompare(a.importedAt));
  const kevOf = r => Object.values(r.product.variants.imported ? r.product.variants.imported.vuln_defs : Object.values(r.product.variants)[0].vuln_defs).filter(d => d.kev).length;
  const stale = recs.filter(r => libIsStale(r, st.days)), third = recs.filter(r => r.origin === "third-party");
  const day = x => (x ? x.slice(0, 10) : "");
  const kpi = (lab, val, cls = "") => `<div class="kpi"><span class="muted small">${esc(lab)}</span><b class="${cls}">${val}</b></div>`;
  const rowHtml = r => { const v = Object.values(r.product.variants)[0], e = v.history[0], kv = kevOf(r), isStale = r.checkedAt && libIsStale(r, st.days);
    return `<tr data-id="${esc(r.id)}"><td><b>${esc(r.brief.name)}</b><br><span class="small muted">${esc(r.srcName)} · ${esc(v.sbom.format)}</span></td>
      <td><span class="badge ${r.origin === "third-party" ? "no" : ""}">${esc(t(r.origin === "third-party" ? "lib.third_party" : "lib.own"))}</span>${r.sourceLabel ? `<br><span class="small">${esc(r.sourceLabel)}</span>` : ""}</td><td>${e.components}</td>
      <td class="small">${r.checkedAt ? `${e.vuln_total} CVE${kv ? ` · <b class="no">KEV ×${kv}</b>` : ""}${e.dq.pending + e.dq.unmatched + e.dq.none ? `<br><span class="muted">${esc(t("lib.not_covered", {n: e.dq.pending + e.dq.unmatched + e.dq.none}))}</span>` : ""}` : `<span class="no">${esc(t("lib.not_checked"))}</span>`}</td>
      <td class="small">${esc(day(r.importedAt))}</td><td class="small">${r.checkedAt ? esc(day(r.checkedAt)) : esc(t("lib.never"))}${isStale ? ` <span class="badge no">${esc(t("lib.stale"))}</span>` : ""}${r.lastError ? `<br><span class="no">${esc(t("lib.check_fail", {msg: r.lastError}))}</span>` : ""}</td>
      <td><div class="row" style="gap:6px;flex-wrap:wrap"><a class="btn" href="${link(["p", r.id, Object.keys(r.product.variants)[0]])}">${esc(t("lib.open"))}</a><button data-act="check">${esc(t("lib.check"))}</button><button data-act="dl">${esc(t("lib.download"))}</button><button data-act="rm" class="linkish no">${esc(t("lib.remove"))}</button></div></td></tr>`; };
  $app.innerHTML = `<h2>📚 ${esc(t("lib.title"))}</h2><p class="muted">${esc(t("lib.lead"))}</p>
    ${libAvailable ? "" : `<div class="card warn"><b>${esc(t("lib.nostorage"))}</b></div>`}
    <div class="kpis">${kpi(t("lib.kpi.total"), recs.length)}${kpi(t("lib.kpi.third"), third.length)}${kpi(t("lib.kpi.kev"), recs.filter(r => kevOf(r)).length, recs.some(r => kevOf(r)) ? "no" : "ok")}${kpi(t("lib.kpi.stale"), stale.length, stale.length ? "no" : "ok")}</div>
    <div class="card"><h3 style="margin:0 0 8px">${esc(t("lib.import"))}</h3>
      <div id="libDrop" class="drop" tabindex="0" role="button" aria-label="${esc(t("lib.drop"))}">${esc(t("lib.drop"))}<input type="file" id="libFile" multiple accept=".json,application/json" hidden></div>
      <label class="blk" style="margin-top:10px">${esc(t("lib.paste"))}<textarea id="libText" rows="3" spellcheck="false" style="width:100%;font-family:monospace"></textarea></label>
      <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr))"><label class="blk">${esc(t("lib.name"))}<input id="libName" maxlength="80" placeholder="${esc(t("lib.name_ph"))}"></label>
        <label class="blk">${esc(t("lib.origin"))}<select id="libOrigin"><option value="own">${esc(t("lib.own"))}</option><option value="third-party">${esc(t("lib.third_party"))}</option></select></label>
        <label class="blk">${esc(t("lib.source_label"))}<input id="libSource" maxlength="80" placeholder="${esc(t("lib.source_ph"))}"></label></div>
      <label class="small" style="display:block;margin:6px 0"><input type="checkbox" id="libCheckBox" checked> ${esc(t("lib.check_box"))}</label>
      <div class="row"><button class="primary" id="libGo">${esc(t("lib.import_btn"))}</button><span id="libMsg" class="small" aria-live="polite"></span></div>
      <p class="small muted">${esc(t("lib.privacy"))}</p></div>
    <div class="card" style="margin-top:14px"><h3 style="margin:0 0 8px">${esc(t("lib.updates"))}</h3>
      <label class="small"><input type="checkbox" id="libAuto" ${st.auto ? "checked" : ""}> ${esc(t("lib.auto"))}</label>
      <label class="small" style="margin-left:10px">${esc(t("lib.auto_days"))} <select id="libDays">${[1, 3, 7, 14, 30].map(d => `<option value="${d}" ${st.days === d ? "selected" : ""}>${d}</option>`).join("")}</select></label>
      <button id="libStale" style="margin-left:10px" ${stale.length ? "" : "disabled"}>${esc(t("lib.check_stale", {n: stale.length}))}</button><p class="small muted" style="margin:6px 0 0">${esc(t("lib.auto_h"))}</p></div>
    <h3 style="margin-top:14px">${esc(t("lib.your"))}</h3>
    ${recs.length ? `<div class="tablewrap"><table><thead><tr><th>${esc(t("lib.col.name"))}</th><th>${esc(t("lib.col.origin"))}</th><th>${esc(t("lib.col.components"))}</th><th>${esc(t("lib.col.vulns"))}</th><th>${esc(t("lib.col.imported"))}</th><th>${esc(t("lib.col.checked"))}</th><th></th></tr></thead><tbody id="libRows">${recs.map(rowHtml).join("")}</tbody></table></div>` : `<p class="muted">${esc(t("lib.empty"))}</p>`}`;

  const msg = (ok, x) => { const m = document.getElementById("libMsg"); if (m) { m.className = "small " + (ok ? "ok" : "no"); m.textContent = x; } };
  const progress = step => msg(true, t("lib.step." + step));
  const checkOne = async id => { try { const s = await libCheck(id, progress); msg(true, t("lib.checked_ok", {cves: s.cves, kev: s.kev})); return true; } catch (e) { msg(false, t("lib.check_fail", {msg: e.message})); return false; } };
  const importFiles = async files => {
    const origin = document.getElementById("libOrigin").value, sourceLabel = document.getElementById("libSource").value, name = files.length === 1 ? document.getElementById("libName").value : "", check = document.getElementById("libCheckBox").checked;
    let done = 0;
    for (const f of files) {
      try { const rec = await libImportText(f.text, f.name, {name, origin, sourceLabel}); done++; if (check) await checkOne(rec.id); }
      catch (e) { msg(false, t("lib.err", {file: f.name, msg: e.message})); if (files.length === 1) return; }
    }
    if (done) { msg(true, t("lib.imported_ok", {n: done})); await libraryView(); }
  };
  const drop = document.getElementById("libDrop"), input = document.getElementById("libFile");
  const readAll = list => Promise.all([...list].slice(0, 20).map(f => f.slice(0, LIB_MAX_BYTES + 1).text().then(text => ({name: f.name, text}))));
  drop.onclick = () => input.click(); drop.onkeydown = e => { if (e.key === "Enter" || e.key === " ") input.click(); };
  input.onchange = async () => { if (input.files.length) importFiles(await readAll(input.files)); };
  ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", async e => { if (e.dataTransfer.files.length) importFiles(await readAll(e.dataTransfer.files)); });
  document.getElementById("libGo").onclick = () => { const text = document.getElementById("libText").value; if (!text.trim()) { msg(false, t("lib.nothing")); return; } importFiles([{name: "pasted-sbom.json", text}]); };
  document.getElementById("libAuto").onchange = e => { libSaveSettings({...libSettings(), auto: e.target.checked}); };
  document.getElementById("libDays").onchange = async e => { libSaveSettings({...libSettings(), days: +e.target.value}); await libraryView(); };
  document.getElementById("libStale").onclick = async () => { let n = 0; for (const r of stale) if (await checkOne(r.id)) n++; if (n) await libraryView(); };
  const rows = document.getElementById("libRows");
  if (rows) rows.onclick = async e => {
    const b = e.target.closest("button[data-act]"); if (!b) return; const id = b.closest("tr").dataset.id, rec = recs.find(r => r.id === id);
    if (b.dataset.act === "check") { b.disabled = true; if (await checkOne(id)) await libraryView(); else b.disabled = false; }
    else if (b.dataset.act === "dl") downloadBlob(rec.srcName || "sbom.json", rec.source, "application/json");
    else if (b.dataset.act === "rm" && confirm(t("lib.confirm_remove", {name: rec.brief.name}))) { await libDeleteRecord(id); await libChanged(); await libraryView(); }
  };
}

if (typeof module !== "undefined" && module.exports) module.exports = {libNormalize, libBuildProduct, libBrief, libCvss3, libOsvSeverity, libEnrich, libAgeDays, libSlug, libPurlType, LIB_MAX_VULN_IDS, LIB_POC_MAX, LIB_OSV_TYPE_LIST};
