# SBOMs of this app

Generated with Syft 1.54.1 and scanned with Grype 0.120.1 (DB built 2026-10-15) by `scripts/make-sbom.sh`.

| File | What it inventories | Components | Grype matches |
|---|---|---|---|
| `sbomnix-explorer.cdx.json` / `.spdx.json` | The repository: GitHub Actions used by the workflows, plus the `sbomnix` package | 29 | 0 |
| `sbomnix-python-deps.cdx.json` | The Python packages installed in the project's `.venv` (all 15 dependencies from `pyproject.toml` plus their dependencies and the dev/test tooling) | 62 | 0 |
| `*.grype.json` | Grype reports for the above | | |

## What "0 matches" does and does not mean
- Grype itself works: on `docs/reference-sbom/reference.cdx.json` (known-vulnerable components) it reports 67 matches.
- The Explorer web app (`docs/`) and the upload worker (`worker/`) have **no third-party packages**: plain JavaScript, no `package.json`, no CDN scripts. Nothing to inventory there.
- `pyproject.toml` lists dependencies without versions and there is no lockfile, so the repository SBOM cannot know them. The venv SBOM shows what is actually installed on one machine; it includes dev tooling (pytest, playwright) and will differ elsewhere.
- This is a Nix project: for the real build/runtime closure use `sbomnix` itself on the flake output (`sbomnix .#sbomnix`), which this Syft scan does not see.
- 17 of the 23 GitHub Action references are pinned to a commit SHA; the other 6 use a tag only (`actions/checkout@v4`, `actions/upload-artifact@v4`, `actions/configure-pages@v5`, `actions/deploy-pages@v4`, `actions/upload-pages-artifact@v3`; in `pages.yml` and `cve-check.yml`) and could be pinned. Grype has little advisory data for Actions, so absence of matches there is weak evidence.

## Not done
- Cosign signing/attestation: needs a signing key (or keyless OIDC) and a registry image to attach to. This app is not published as a container image.
- CI gate: `FAIL_ON=high scripts/make-sbom.sh` is ready to call from a workflow; none is wired yet.
