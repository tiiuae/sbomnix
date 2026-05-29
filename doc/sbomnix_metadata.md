<!--
SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# sbomnix metadata enrichment

`sbomnix` can enrich SBOM components with nixpkgs package metadata such as
descriptions, licenses, maintainers, and homepage links. Metadata enrichment is
best-effort: an SBOM can still be generated when metadata is unavailable or when
no metadata candidate matches a component exactly.

## Metadata source selection

For flakeref targets, `sbomnix` selects a nixpkgs metadata source from the
target context. For NixOS toplevel flakerefs, it uses the evaluated
`nixosConfigurations.<name>.pkgs` package set, so overlays, package overrides,
nixpkgs config, and system-specific settings can be represented.

For other flakeref targets, `sbomnix` uses the target flake lock graph to find
the pinned nixpkgs source. Store-path targets skip nixpkgs metadata because a
store path does not identify which nixpkgs source produced it.

## Component matching

Component names, pnames, and versions are used as lookup hints to find possible
nixpkgs derivations. Those names are not trusted as the final match. The
metadata helper returns derivation and output identities, and `sbomnix` accepts
metadata only when the returned `drvPath` or `outPath` matches an SBOM component
exactly.

This keeps metadata enrichment tied to the actual components in the SBOM while
still allowing targeted lookups in package sets.

## Flake input packages

Some targets include packages that come from flake inputs rather than the
primary nixpkgs package set. After scanning the selected package set, `sbomnix`
may scan package roots exported by the target flake inputs for components that
remain unmatched.

## CPE sources

When nixpkgs metadata is available, `sbomnix` prefers exact CPE identifiers
from nixpkgs metadata and falls back to heuristic CPE matching only when
nixpkgs metadata does not provide a canonical CPE. The heuristic fallback can
be disabled with `--exclude-cpe-matching`, while `--exclude-meta` disables
nixpkgs metadata entirely, including metadata-derived CPEs.

Nixpkgs may also expose `possibleCPEs` guesses alongside its canonical CPE
metadata. `sbomnix` keeps those guesses diagnostic-only and does not export them
as the final component CPE.

## Caching and diagnostics

Package metadata lookups are cached by metadata source identity, lookup set,
lookup mode, and helper implementation fingerprint. With `-v`, `sbomnix` logs
the selected metadata source, lookup counts, and whether package metadata came
from a cache hit or a fresh scan.

CycloneDX and SPDX outputs record the selected metadata source in document
metadata, including fields such as `nixpkgs:metadata_source_method`,
`nixpkgs:path`, `nixpkgs:rev`, `nixpkgs:flakeref`, `nixpkgs:version`, and
`nixpkgs:message`.
