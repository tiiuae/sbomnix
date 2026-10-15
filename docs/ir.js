"use strict";
/* SBOM Explorer — incident-response triage of CVEs: which are exploited in the wild (KEV), which only have a public PoC,
   which are merely likely, and which are routine. Pure functions first (testable in node), UI below.
   A tier says how urgent a vulnerability is. It never says an incident has happened: that needs evidence from YOUR environment. */

const IR_EPSS_LIKELY = 0.10;  // FIRST EPSS probability of exploitation within 30 days
const IR_TIERS = ["kev", "poc", "likely", "routine"];

/* def = a vuln_defs entry: {kev, epss, poc: {n, url} | null, ...}. Missing data never raises a tier. */
function irTier(def) {
  def = def || {};
  if (def.kev) return "kev";
  if (def.poc && def.poc.n > 0) return "poc";
  if (typeof def.epss === "number" && def.epss >= IR_EPSS_LIKELY) return "likely";
  return "routine";
}

/* machine-readable reasons behind a tier, for the table and the exported playbook */
function irExplain(def) {
  def = def || {};
  const why = [];
  if (def.kev) why.push({k: "kev", src: def.kev_src || [], date: def.kev_info?.date || null, ransomware: !!def.kev_info?.ransomware});
  if (def.poc && def.poc.n > 0) why.push({k: "poc", n: def.poc.n, url: def.poc.url || ""});
  if (typeof def.epss === "number") why.push({k: "epss", v: def.epss});
  return why;
}

/* Decision tree: tier + three answers ("yes" | "no" | "unknown") -> verdict, priority, ordered checklist.
   deployed: is the component running anywhere we operate?  exposed: reachable by an attacker (internet / untrusted input)?
   evidence: any sign of exploitation or compromise in OUR environment?  Only evidence makes an incident. */
const IR_STEPS = {
  incident: ["declare", "isolate", "preserve", "mitigate", "notify"],
  trigger: ["hunt", "mitigate", "escalate_if_hit", "flag_ciso"],
  find_out: ["ask_steward", "check_exposure", "treat_as_trigger"],
  urgent: ["patch_days", "virtual_patch", "monitor"],
  watch: ["schedule", "detect", "recheck_kev"],
  routine: ["normal_cycle"],
  not_affected: ["record_vex", "remove_unused"]};
function irVerdict({tier, deployed = "unknown", exposed = "unknown", evidence = "unknown"} = {}) {
  const hot = tier === "kev" || tier === "poc";
  let verdict, priority;
  if (evidence === "yes") { verdict = "incident"; priority = hot ? "P1" : "P2"; }
  else if (deployed === "no") { verdict = "not_affected"; priority = "P4"; }
  else if (tier === "kev") {
    if (deployed === "yes" && exposed === "yes") { verdict = "trigger"; priority = "P1"; }
    else if (deployed === "yes" && exposed === "no") { verdict = "urgent"; priority = "P2"; }
    else { verdict = "find_out"; priority = "P2"; }
  }
  else if (tier === "poc") { if (exposed === "yes") { verdict = "urgent"; priority = "P2"; } else { verdict = "watch"; priority = "P3"; } }
  else if (tier === "likely") { verdict = "watch"; priority = "P3"; }
  else { verdict = "routine"; priority = "P4"; }
  return {verdict, priority, steps: IR_STEPS[verdict]};
}

/* ---------- playbook export (markdown, English) ---------- */
const mdCell = x => String(x ?? "").replace(/[\r\n]+/g, " ").replace(/\|/g, "\\|").replace(/[<>`]/g, c => ({"<": "&lt;", ">": "&gt;", "`": "'"})[c]).slice(0, 200);
const IR_TIER_NAME = {kev: "Exploited (KEV)", poc: "Public PoC, not KEV", likely: "Likely (EPSS >= 10%)", routine: "Routine"};
const IR_TIER_PRIO = {kev: "P1 if deployed and reachable, else P2", poc: "P2 if reachable, else P3", likely: "P3", routine: "P4"};
/* ctx: {product, variant, version, date, by, rows: [{id, label, tier, def}], stewards: {componentName: steward}, flags: [{label, reason, note}]} */
function irPlaybookMd(ctx) {
  const rows = ctx.rows || [], stew = ctx.stewards || {}, steward = label => stew[label.split("@")[0]] || "NONE ASSIGNED";
  const count = k => new Set(rows.filter(r => r.tier === k).map(r => r.id)).size, hot = rows.filter(r => r.tier === "kev" || r.tier === "poc");
  const comps = [...new Set(hot.map(r => r.label))], unowned = comps.filter(c => steward(c) === "NONE ASSIGNED");
  const table = (head, body) => [`| ${head.join(" | ")} |`, `|${head.map(() => "---").join("|")}|`, ...body.map(r => `| ${r.map(mdCell).join(" | ")} |`)].join("\n");
  const L = [];
  L.push(`# Incident Response Playbook: exploited and exploitable vulnerabilities in ${mdCell(ctx.product)}`, "",
    "## 1. Playbook metadata", "",
    table(["Field", "Value"], [["Product / variant", `${ctx.product} / ${ctx.variant} ${ctx.version || ""}`], ["Generated", ctx.date], ["Owner", ctx.by || "(assign: SOC manager)"], ["Next review", "3 months after generation, and after every real incident"],
      ["Trigger", "A CVE in this product's SBOM is listed in CISA KEV (or EUVD as exploited), or has a public PoC, or evidence of exploitation appears"], ["Severity", "P1 critical, P2 high, P3 medium, P4 low (see section 3)"]]), "",
    "> **KEV is not an incident.** KEV means attackers exploit the vulnerability somewhere. An incident is evidence of exploitation or compromise in OUR environment.", "",
    "## 2. RACI", "",
    table(["Activity", "SOC L1", "SOC L2", "IR lead", "CISO", "Data steward", "Legal/Comms"], [["Triage the CVE tier", "R", "C", "I", "", "C", ""], ["Confirm deployed/reachable", "C", "R", "A", "", "R", ""], ["Hunt for compromise", "", "R", "A", "I", "C", ""], ["Declare incident", "", "C", "R", "A", "", "I"], ["Patch / mitigate", "", "C", "A", "I", "R", ""], ["Regulatory / customer notice", "", "", "C", "A", "", "R"], ["Lessons learned", "C", "C", "R", "I", "C", "I"]]), "",
    "## 3. Detection and triage", "",
    `Current position from the SBOM (${rows.length} CVE findings):`, "",
    table(["Tier", "CVEs", "Meaning", "Priority"], Object.keys(IR_TIER_NAME).map(k => [IR_TIER_NAME[k], count(k), {kev: "Exploited in the wild", poc: "Exploit code public, no confirmed attacks", likely: "No PoC, EPSS high", routine: "Normal management"}[k], IR_TIER_PRIO[k]])), "",
    "### Priority findings (KEV and public PoC)", "",
    hot.length ? table(["Tier", "CVE", "Component", "Steward", "EPSS", "KEV added", "PoC repos"], hot.map(r => [IR_TIER_NAME[r.tier], r.id, r.label, steward(r.label), typeof r.def.epss === "number" ? (r.def.epss * 100).toFixed(1) + "%" : "n/a", r.def.kev_info?.date || (r.def.kev ? "yes" : ""), r.def.poc?.n ?? "not collected"])) : "_None._", "",
    "### Decision tree", "", "```", "Alert: CVE in KEV / public PoC",
    "|- Evidence of exploitation in our environment?", "|   |- YES -> INCIDENT: declare, P1 (KEV/PoC) or P2, go to section 4", "|   `- NO / unknown",
    "|       |- Component deployed anywhere we run?", "|       |   |- NO  -> not affected: record (VEX), remove if unused", "|       |   `- YES / unknown",
    "|       |       |- Reachable by an attacker?", "|       |       |   |- KEV + YES     -> INCIDENT TRIGGER (P1): hunt for compromise now", "|       |       |   |- KEV + NO      -> urgent patch (P2)", "|       |       |   |- KEV + unknown -> find out first, treat as trigger (P2)", "|       |       |   |- PoC + YES     -> urgent patch (P2)", "|       |       |   `- otherwise     -> watch / routine (P3-P4); re-check weekly for KEV", "```", "",
    "## 4. Containment", "", "1. Isolate affected hosts or block the attack path (network ACL, WAF rule, feature off).", "2. **Preserve evidence before changing anything**: logs, memory, disk image, timestamps.",
    "3. Hunt since the KEV date: exploit strings in web/app logs, new processes, unexpected outbound connections, new accounts or persistence.", "4. Any hit: declare an incident, page the IR lead and the CISO.", "",
    "## 5. Eradication", "", "1. Identify the root cause and the exploited component version from the SBOM.", "2. Upgrade to the fixed version or remove the component; confirm the fix in a new SBOM.", "3. Remove attacker persistence found during the hunt; rotate credentials reachable from the host.", "",
    "## 6. Recovery", "", "1. Restore from a known-good build, regenerate the SBOM and re-scan.", "2. Validate: no finding of this CVE, hunt queries return nothing, monitoring in place.", "3. Heightened monitoring for 30 days.", "",
    "## 7. Post-incident", "", "1. Lessons-learned meeting within 5 working days.", "2. Add detection for the exploited pattern; update this playbook.", "3. Assign a data steward to every package that had none.", "",
    "## 8. Communication", "", table(["Audience", "When", "Owner"], [["IR lead, CISO", "Immediately on KEV trigger or incident", "SOC L2"], ["Data stewards of affected packages", "On triage", "SOC L1"], ["Legal and privacy officer", "If personal data may be involved", "IR lead"], ["Customers / regulators", "As required by law and contract (for example CRA, GDPR); decided by Legal", "CISO"]]), "",
    "Status updates: every 4 hours during a P1, daily during a P2.", "",
    "## 9. Appendices", "", "### Data stewardship", "",
    unowned.length ? `${unowned.length} affected component(s) have no data steward and may become obsolete unwatched: ${unowned.map(mdCell).join(", ")}.` : "Every affected component has a data steward.", "",
    ctx.flags && ctx.flags.length ? ["### Packages flagged for CISO review", "", table(["Package", "Reason", "Note"], ctx.flags.map(f => [f.label, f.reason, f.note]))].join("\n") : "_No packages flagged._", "",
    "### Evidence collection checklist", "", "- [ ] Affected host list and timestamps", "- [ ] Application, web and auth logs for the exposure window", "- [ ] Memory capture and disk image of affected hosts", "- [ ] Network flow / proxy logs", "- [ ] SBOM version and scan report at time of detection", "",
    "### Data sources and limits", "", "- KEV: CISA catalog; EUVD: ENISA; EPSS: FIRST; PoC: public GitHub repositories named after the CVE (nomi-sec/PoC-in-GitHub).",
    "- A PoC match is a name match, not proof of a working exploit. Not being in KEV does not mean a vulnerability is not exploited.", "- Generated from SBOM data; it does not know your network. Confirm deployment and exposure before acting.", "");
  return L.join("\n");
}

/* ---------- UI: product tab "Incident triage" (uses app.js globals at call time) ---------- */
const IR_PILL = {kev: "s-critical", poc: "s-high", likely: "s-medium", routine: "s-unknown"};
function irRows(v) {
  const last = v.history[v.history.length - 1], seen = new Map();
  (last.cve_pairs || []).forEach(([id, , , label]) => { const k = id + "|" + label; if (!seen.has(k)) seen.set(k, {id, label, def: v.vuln_defs[id] || {}}); });
  const rows = [...seen.values()].map(r => ({...r, tier: irTier(r.def)}));
  return rows.sort((a, b) => IR_TIERS.indexOf(a.tier) - IR_TIERS.indexOf(b.tier) || (b.def.epss || 0) - (a.def.epss || 0));
}
function irTab(p, v) {
  const rows = irRows(v), counts = Object.fromEntries(IR_TIERS.map(k => [k, new Set(rows.filter(r => r.tier === k).map(r => r.id)).size]));
  const hasPoc = Object.values(v.vuln_defs).some(d => "poc" in d);
  const kpi = k => `<div class="kpi"><span class="pill ${IR_PILL[k]}">${esc(t("ir.tier." + k))}</span><b>${counts[k]}</b><span class="small muted">${esc(t("ir.tier." + k + "_d"))}</span></div>`;
  return `<div class="card warn" style="margin-bottom:14px"><h3 style="margin:0 0 6px">🚨 ${esc(t("ir.statement_title"))}</h3><p class="small" style="margin:0 0 6px">${esc(t("ir.statement"))}</p><p class="small" style="margin:0"><b>${esc(t("ir.statement_rule"))}</b></p></div>
  <div class="kpis">${IR_TIERS.map(kpi).join("")}</div>
  ${triageCard(rows)}
  ${v.components.some(c => c[6] === "osv" || c[6] === "nvd") ? "" : `<div class="card warn" style="margin-bottom:10px"><b>${esc(t("ir.nodata"))}</b></div>`}
  ${hasPoc ? "" : `<p class="small no">${esc(t("ir.nopoc"))}</p>`}
  <div class="row" style="margin-bottom:8px"><button id="irPlaybook">⬇ ${esc(t("ir.playbook"))}</button><span class="small muted">${esc(t("ir.playbook_h"))}</span></div>
  <div class="row"><select id="irFilter" aria-label="${esc(t("ir.tier_col"))}"><option value="">${esc(t("ir.f_all"))}</option>${IR_TIERS.map(k => `<option value="${k}">${esc(t("ir.tier." + k))}</option>`).join("")}</select><span id="irCount" class="small muted"></span></div>
  <div class="tablewrap"><table><thead><tr><th>${esc(t("ir.tier_col"))}</th><th>${esc(t("cmp.cve"))}</th><th>${esc(t("cmp.package"))}</th><th>EPSS</th><th>KEV</th><th>PoC</th><th>EUVD</th></tr></thead><tbody id="irBody"></tbody></table></div>
  <p class="small muted">${esc(t("ir.poc_caveat"))}</p>`;
}
function triageCard(rows) {
  const ids = [...new Map(rows.map(r => [r.id, r])).values()], yn = id => `<label class="blk">${esc(t("ir.q." + id))}<select id="irQ_${id}"><option value="unknown">${esc(t("ir.a.unknown"))}</option><option value="yes">${esc(t("ir.a.yes"))}</option><option value="no">${esc(t("ir.a.no"))}</option></select></label>`;
  return `<div class="card" style="margin-bottom:14px"><h3 style="margin:0 0 6px">🧭 ${esc(t("ir.triage_title"))}</h3><p class="small muted" style="margin:0 0 8px">${esc(t("ir.triage_lead"))}</p>
    <label class="blk">${esc(t("ir.q.cve"))}<select id="irCve">${ids.map(r => `<option value="${esc(r.id)}">${esc(t("ir.tier." + r.tier))} · ${esc(r.id)} · ${esc(r.label)}</option>`).join("")}</select></label>
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))">${yn("deployed")}${yn("exposed")}${yn("evidence")}</div>
    <div id="irVerdict" class="card" style="margin-top:10px" aria-live="polite"></div></div>`;
}
function wireTriage(v) {
  const rows = irRows(v), q = id => document.getElementById("irQ_" + id), sel = document.getElementById("irCve"), out = document.getElementById("irVerdict");
  if (!sel) return;
  const run = () => {
    const r = rows.find(x => x.id === sel.value), res = irVerdict({tier: r ? r.tier : "routine", deployed: q("deployed").value, exposed: q("exposed").value, evidence: q("evidence").value});
    out.dataset.verdict = res.verdict;
    out.innerHTML = `<div class="row" style="gap:10px"><span class="pill ${res.verdict === "incident" || res.priority === "P1" ? "s-critical" : res.priority === "P2" ? "s-high" : res.priority === "P3" ? "s-medium" : "s-unknown"}">${res.priority}</span><b>${esc(t("ir.v." + res.verdict))}</b></div>
      <p class="small" style="margin:6px 0">${esc(t("ir.v." + res.verdict + "_d"))}</p><ol class="small" style="margin:0;padding-left:1.2em">${res.steps.map(k => `<li>${esc(t("ir.step." + k))}</li>`).join("")}</ol>
      <div class="row" style="margin-top:8px"><button id="irRecord">${esc(t("ir.record"))}</button><span id="irRecorded" class="small ok"></span></div>`;
    document.getElementById("irRecord").onclick = () => { recordDecision(CUR.pid, sel.value, {verdict: res.verdict, priority: res.priority, deployed: q("deployed").value, exposed: q("exposed").value, evidence: q("evidence").value}); document.getElementById("irRecorded").textContent = t("ir.recorded"); };
  };
  [sel, q("deployed"), q("exposed"), q("evidence")].forEach(e => e.onchange = run); run();
}

function wireIr(v) {
  wireTriage(v);
  const rows = irRows(v), body = document.getElementById("irBody"), f = document.getElementById("irFilter"), c = document.getElementById("irCount");
  const draw = () => {
    const list = rows.filter(r => !f.value || r.tier === f.value);
    c.textContent = t("ir.count", {n: list.length, total: rows.length}) + (list.length > 300 ? t("comp.first") : "");
    body.innerHTML = list.slice(0, 300).map(r => { const d = r.def, e = d.euvd;
      return `<tr><td><span class="pill ${IR_PILL[r.tier]}" style="white-space:nowrap">${esc(t("ir.tier." + r.tier))}</span></td>
        <td><a href="https://osv.dev/vulnerability/${encodeURIComponent(d.osv || r.id)}" target="_blank" rel="noopener">${esc(r.id)}</a></td><td><code>${esc(r.label)}</code></td>
        <td>${typeof d.epss === "number" ? (d.epss * 100).toFixed(d.epss < 0.01 ? 2 : 1) + "%" : "—"}</td>
        <td class="small">${d.kev ? `<b class="no">${esc(t("ir.kev_yes"))}</b>${d.kev_info?.date ? ` · ${esc(d.kev_info.date)}` : ""}${d.kev_info?.ransomware ? ` · <span class="badge no">${esc(t("ir.ransom"))}</span>` : ""}` : "—"}</td>
        <td class="small">${d.poc && d.poc.n ? `<a href="${esc(d.poc.url)}" target="_blank" rel="noopener">${d.poc.n} ↗</a>` : "poc" in d ? "—" : "?"}</td>
        <td class="small">${e && e.id ? `<a class="badge" style="white-space:nowrap" href="https://euvd.enisa.europa.eu/vulnerability/${encodeURIComponent(e.id)}" target="_blank" rel="noopener">${esc(e.id)}</a>` : "—"}</td></tr>`; }).join("");
  };
  f.onchange = draw; draw();
  document.getElementById("irPlaybook").onclick = () => {
    const rv = typeof review !== "undefined" ? review : {stewards: {}, flags: {}, by: ""}, pid = CUR.pid, stewards = {};
    Object.entries(rv.stewards).forEach(([k, who]) => { if (k.startsWith(pid + "|")) stewards[k.slice(pid.length + 1)] = who; });
    const flags = Object.entries(rv.flags).filter(([k]) => k.startsWith(pid + "|" + CUR.vid + "|")).map(([k, f]) => ({label: k.split("|")[2], reason: f.reason, note: f.note}));
    const last = v.history[v.history.length - 1];
    downloadBlob(`ir-playbook-${pid}-${CUR.vid}.md`, irPlaybookMd({product: CUR.p.name, variant: v.label, version: last.version, date: new Date().toISOString().slice(0, 10), by: rv.by, rows, stewards, flags}), "text/markdown");
  };
}

if (typeof module !== "undefined" && module.exports) module.exports = {irTier, irExplain, irVerdict, irPlaybookMd, IR_STEPS, IR_TIERS, IR_EPSS_LIKELY};
