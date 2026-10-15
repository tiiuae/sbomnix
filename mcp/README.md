# SBOM Explorer MCP server

Lets Claude, or any client that speaks the [Model Context Protocol](https://modelcontextprotocol.io), ask questions about the SBOMs in the Explorer and call its API: *which of my CVEs are exploited in the wild, is this an incident, which licences do I ship, who supplies this component.*

It is one file, `mcp/server.js`: Node 18+, no npm packages, stdio transport. All tools are **read-only**. It reuses the Explorer's own code (incident tiers, verdicts, licence classes, policy, supply chain, exports), so an AI gets the same answers as the web UI.

## Connect it

**Claude Code** (this repository): `.mcp.json` is already here. Start `claude` in the repository and approve the `sbom-explorer` server when asked. Check with `claude mcp list`.
To use it from any folder: `claude mcp add sbom-explorer -- node /absolute/path/to/mcp/server.js`

**Claude Desktop** or another client: add to its MCP configuration
```json
{ "mcpServers": { "sbom-explorer": { "command": "node", "args": ["/absolute/path/to/sbomnix/mcp/server.js"] } } }
```

## Where the data comes from
| Variable | Meaning |
|---|---|
| *(none)* | `docs/data/` of this repository |
| `SBOM_EXPLORER_DATA` | another folder with the same layout (`manifest.json`, `<product>.json`, `licenses.json`) |
| `SBOM_EXPLORER_URL` | a hosted Explorer, for example `https://<user>.github.io/sbomnix/` (the server reads `<url>/data/...`) |
| `SBOM_RISK_API_URL` | your worker, for example `https://sbom-explorer-upload.<you>.workers.dev`; enables `risk_average_api` |

These are set by **you**, in the client configuration. No tool argument can change a URL, so a model that has been prompt-injected cannot send your SBOM data to a server of its choosing. `risk_average_api` accepts only an `https://` URL or `http://localhost`.

## Tools
| Tool | What it answers |
|---|---|
| `list_products` | which SBOMs exist, with counts |
| `get_product` | one product: versions, severity counts, incident tiers, maturity, data gaps |
| `list_vulnerabilities` | CVEs by tier (`kev`, `poc`, `likely`, `routine`) with CVSS, EPSS, KEV date, PoC count, EUVD id; filters `tier`, `min_severity`, `limit` |
| `search_cve` | where a CVE occurs across all products |
| `triage_cve` | **is it an incident?** tier + `deployed` / `exposed` / `evidence` answers → verdict, P1-P4, checklist |
| `check_policy` | licence and security policy: forbidden licences, missing licences, KEV, severity limit, unchecked components |
| `licenses` | licence classes, obligations, attribution duty |
| `supply_chain` | dependency tiers, suppliers, components with no supplier |
| `export_sbom` | CycloneDX 1.4 (with VEX), components only, or SPDX 2.3 |
| `analyze_snippet` | licence declared by a piece of source code, with status against the default policy |
| `risk_average` | average CVSS base score from the data in the Explorer (no network) |
| `risk_average_api` | the same through the worker's `POST /sbomRiskAverage` (NVD lookup by CPE; only components with a CPE) |

Resources: `sbom-explorer://manifest` and `sbom-explorer://product/<id>` (a summary).

Try: *"List the products, then show me the KEV-tier vulnerabilities of cve-reference-app and tell me whether CVE-2021-44228 is an incident if the component is deployed and reachable but we have seen nothing."*

## Behaviour you should know
- **KEV is not an incident.** The server tells the model so, and `triage_cve` returns *incident* only when you answer `evidence: yes`. Unknown answers are never read as yes.
- **Not checked is not clean.** Unchecked components, missing licences and PoC data that was not collected come back as unchecked, unknown or `null`, never as zero or safe.
- **Untrusted text.** CVE summaries, component names and licence fields come from third-party SBOMs and databases. The server's instructions tell the model to treat them as data, not instructions; a client that shows tool output to a model should keep doing so.
- **Big exports are refused**, not truncated: a partial SBOM that looks complete is worse than none. Anything over 150,000 characters (for example every export of the 1,196-component demo) returns advice to use the Explorer's Compliance tab. Other results are capped at 100,000 characters; narrow with `limit`, `tier` or `min_severity`.
- Product ids are validated (`letters, digits, . _ -`) and must be in the manifest: no path traversal.
- Diagnostics go to stderr only; stdout carries nothing but protocol messages.

## Tests
`pytest tests/test_mcp_server.py` starts the server and speaks the protocol to it: handshake and version negotiation, every tool on the real data, protocol errors, path-traversal and bad-argument attempts, remote-data mode and the risk API against local stand-in servers.
