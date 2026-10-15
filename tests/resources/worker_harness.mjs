// Drives worker/src/index.js with a scenario from stdin; NVD is mocked and the rate-limit sleep is disabled. Prints {status, body, calls}.
import { pathToFileURL } from "node:url";
const sc = JSON.parse(await new Promise((res) => { let s = ""; process.stdin.on("data", (d) => (s += d)); process.stdin.on("end", () => res(s)); }));
globalThis.setTimeout = (fn) => { fn(); return 0; };
const calls = [];
globalThis.fetch = async (url, init = {}) => {
  const u = new URL(url);
  if (u.hostname !== "services.nvd.nist.gov") throw new Error("unexpected fetch to " + url);
  const cpe = u.searchParams.get("cpeName");
  calls.push({ cpe, apiKey: (init.headers || {}).apiKey || null, hasIsVulnerable: u.searchParams.has("isVulnerable") });
  const r = (sc.nvd || {})[cpe] || { status: 200, vulns: [] };
  if (r.status !== 200) return new Response("{}", { status: r.status });
  return new Response(JSON.stringify({ vulnerabilities: r.vulns.map((v) => ({ cve: { id: v.id, metrics: v.metrics || {} } })) }), { status: 200 });
};
const worker = (await import(pathToFileURL(sc.worker).href)).default;
const headers = { Origin: "https://andrzej-piotrowski-pl.github.io", ...(sc.headers || {}) };
let body;
if (sc.raw !== undefined) body = sc.raw;
else if (sc.nofile) { body = new FormData(); body.append("other", "x"); }
else if (sc.file !== undefined) { body = new FormData(); body.append("file", new Blob([typeof sc.file === "string" ? sc.file : JSON.stringify(sc.file)], { type: "application/json" }), "sbom.json"); }
const req = new Request("https://w.test" + (sc.path || "/sbomRiskAverage"), { method: sc.method || "POST", headers, body: sc.method === "GET" || sc.method === "OPTIONS" ? undefined : body });
const res = await worker.fetch(req, sc.env || {});
const text = await res.text();
process.stdout.write(JSON.stringify({ status: res.status, cors: res.headers.get("access-control-allow-origin"), body: text ? JSON.parse(text) : null, calls }));
