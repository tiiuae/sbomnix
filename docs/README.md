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
