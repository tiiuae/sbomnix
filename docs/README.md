# SBOM Explorer (site/) · PL / EN

Static, build-free web app for the SBOMs of **any product** (desktop, mobile, web, embedded, server, library). Phone + desktop, light/dark, PL/EN switch, first-visit guided tour (“?” replays it), swipeable presentation mode (`#/present/<product>/<variant>`).
Statyczna aplikacja do SBOM-ów **dowolnych produktów**, z przełącznikiem PL/EN, przewodnikiem po pierwszym wejściu i trybem prezentacji.

```
python tools/import_sbom.py bom.json --product my-app --name "My App" --type mobile --version 1.0.0 --variant android
python tools/build_site.py            # data/*.json (OSV.dev + CISA KEV + EPSS, cached); --offline = cache only
python -m http.server -d site 8099    # http://localhost:8099
```

Files: `index.html` · `app.js` (views, tour) · `i18n.js` (all PL/EN text) · `style.css` · `data/` (generated, don't edit).
Full guide / pełny przewodnik: [`docs/ADDING-A-PRODUCT.md`](../docs/ADDING-A-PRODUCT.md). Repo working rules: [`CLAUDE.md`](../CLAUDE.md).
Hosting: `.github/workflows/pages.yml` → GitHub Pages (Settings → Pages → Source: GitHub Actions).

## Reference SBOM and CVE check
`docs/reference-sbom/reference.cdx.json` is a static CycloneDX SBOM with four deliberately outdated components (log4j-core, requests, lodash, openssl), each with a purl, a CPE and an `expected-cve` property. Check any SBOM, including this one, against OSV, NVD and the EU vulnerability database (EUVD, ENISA):

```
python scripts/cve-check.py docs/reference-sbom/reference.cdx.json --out report   # writes report.json + report.md
python scripts/cve-check.py bom.json --no-nvd                                      # skip the slow NVD step
```
Components with `expected-cve` are self-tested: exit code 1 if a lookup source stops finding them. `.github/workflows/cve-check.yml` runs this weekly and uploads the report (add an `NVD_API_KEY` secret for faster NVD calls). Test: `pytest tests/test_cve_check.py -m network`.

### EU data in the Explorer
`scripts/cve-check.py ... --explorer-product cve-reference-app --euvd-max 100` also writes `docs/data/cve-reference-app.json` (demo product *cve-reference-app*): every CVE carries its EUVD ID, score, exploited flag and EPSS; the Compare tab shows an EUVD link and an "exploited (EUVD)" badge, and the VEX template export lists the EUVD reference. It refuses to write if any lookup failed, so a flaky network never shrinks the data. `scripts/euvd-enrich.py docs/data/<id>.json` adds the same `euvd` field to any existing product. EUVD sends no CORS headers, so this is a build-time step, not a browser call.

### Settings page (`#/settings`, ⚙ in the header)
Set your own API endpoints, stored in the browser's localStorage (`sbom-settings`) and applied after *Save and reload*: upload worker URL, collection server (API base), OSV endpoint, NVD endpoint and an EUVD proxy URL. The page has four tabs (`#/settings/status|backend|databases|lookup`): **Status** shows one coloured card per API and checks them all when opened; **Backend** and **Databases** edit the URLs, each with a **Test** button; **Live lookup** asks all configured databases about one CVE. NVD API keys are deliberately not accepted here (NVD rejects browser preflight requests that carry a key); use `NVD_API_KEY` with `scripts/cve-check.py`. EUVD sends no CORS headers, so the browser needs a proxy: `worker/src/index.js` has a `GET /api/euvd?text=CVE-…` route for that (redeploy the worker with `wrangler deploy` to enable it).

### Package review: stewards, flags, CISO page, quick check
- **Data stewards** (Components tab, *Steward* column): assign a person/team per package, or bulk-assign to the shown rows. A statement on the tab and on the CISO page explains the risk: packages without a steward are watched by nobody and can silently become obsolete. Filter *No steward* to see them.
- **Flag as possibly defective** (⚑ column): reason (possibly defective, obsolete, suspicious origin, licence, other) plus a note for the CISO.
- **CISO review** (`#/ciso`, 🛡 in the header): all flagged packages with worst severity, CVE count, EUVD exploited flag and steward; Print/PDF, CSV, JSON, and *Copy link for the CISO*. The link carries the flagged list inside the URL (no server); the recipient sees a read-only snapshot with live CVE data from this site.
- **Quick check** (`#/check`): drop or paste any CycloneDX/SPDX JSON; it is read in the browser and only package URLs go to the OSV endpoint (see Settings). Packages without a purl or in ecosystems OSV does not cover are reported as *not checked*, never as clean. Packages can be flagged straight from the results.
All of this state is kept in the browser (`localStorage` key `sbom-review`).

### Incident triage (product tab *Incident triage*, `#/p/<product>/<variant>/ir`)
Separates CVEs by how urgent they are, and says plainly that **KEV is not an incident**: KEV means attackers exploit the vulnerability somewhere; an incident is evidence of exploitation or compromise in *your* environment.
- **Tiers** (`docs/ir.js`, `irTier`): *Exploited (KEV)* (CISA KEV or EUVD), *Public PoC, not KEV*, *Likely* (EPSS ≥ 10%), *Routine*. Missing data never raises a tier.
- **Is this an incident?** card: pick a CVE, answer three questions (deployed? reachable? evidence of compromise?) and get a verdict with priority P1–P4 and an ordered checklist (`irVerdict`). Only a "yes" on evidence yields *incident*; KEV + deployed + reachable yields *incident trigger* (hunt for compromise now).
- **Download IR playbook (.md)**: nine-section playbook generated from the product's SBOM data, data stewards and CISO flags (English; the button and page are PL/EN).
- **Data**: `scripts/cve-check.py ... --explorer-product <id>` writes `kev`, `kev_info`, `epss` and `poc` per CVE (CISA KEV, FIRST EPSS, nomi-sec/PoC-in-GitHub). Products built before this have no PoC data; the tab says so. If KEV/EPSS/PoC cannot be fetched, the build fails instead of writing incomplete data.
- **Limits**: a PoC match is a name match on public GitHub repositories, not proof of a working exploit. Not being in KEV does not mean a CVE is not exploited. The tab does not know your network: deployment and exposure are your answers.
- Tests: `pytest tests/test_ir_triage.py tests/test_ir_i18n.py` (the second fails if any IR string lacks an English or Polish translation).
