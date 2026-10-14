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
