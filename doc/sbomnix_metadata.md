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

Metadata is accepted only by derivation identity: a nixpkgs derivation
provides metadata for an SBOM component when its `drvPath` or one of its
output paths equals the component's derivation or output path. Component
names are never trusted as a match on their own.

`sbomnix` finds the derivations in one Nix evaluation:

1. It walks the derivation values reachable from the flake target through
   derivation attributes such as `buildInputs`. This finds exactly the
   derivations the target was built from, including overridden packages,
   bootstrap packages, and packages from flake inputs.
2. For components the walk does not reach, such as dependencies referenced
   only through string context, or reaches only as a value without a description,
   component names, pnames, and versions are used as hints for attribute
   lookups in the selected package set. A candidate is used only when its
   identity matches the component.
3. The derivations found by name are walked as well, which finds their
   dependencies that no attribute name leads to.

The first step is skipped when the SBOM contains a NixOS system, as it does
for NixOS toplevels and for images that reference one: a NixOS system
references its packages only through string context, so the walk would
evaluate the whole system a second time and find next to nothing. The target
itself then gets metadata only when an attribute name leads to it.

Runtime and buildtime SBOMs use the same lookup, so a derivation gets the same
metadata in both.

## Flake input packages

Some targets include packages that come from flake inputs rather than the
primary nixpkgs package set. When a component is not found in the selected
package set or in the package outputs of the target flake, `sbomnix` also
looks it up in the package outputs of the target flake inputs.

## CPE sources

When nixpkgs metadata is available, `sbomnix` prefers exact CPE identifiers
from nixpkgs metadata and falls back to heuristic CPE matching only when
nixpkgs metadata does not provide a canonical CPE. The heuristic fallback can
be disabled with `--exclude-cpe-matching`, while `--exclude-meta` disables
nixpkgs metadata entirely, including metadata-derived CPEs.

The heuristic itself consults a small curated table of package names whose
canonical CPE identity cannot be derived from the CPE dictionary, either
because the name is absent from it or because the product name maps to several
vendors. Nixpkgs metadata still takes precedence over the curated identity.

Nixpkgs may also expose `possibleCPEs` guesses alongside its canonical CPE
metadata. `sbomnix` keeps those guesses diagnostic-only and does not export them
as the final component CPE.

## Caching and diagnostics

Package metadata lookups are cached by metadata source identity, target,
component set, and helper implementation fingerprint, so repeating a scan does
not evaluate nixpkgs again. With `-v`, `sbomnix` logs the selected metadata
source, lookup counts, and whether package metadata came from a cache hit or a
fresh scan.

If the evaluation fails in the target flake or in one of its inputs, `sbomnix`
retries the lookup without the target walk and without the package outputs of
flake inputs. The result of such a retry is not cached.

CycloneDX and SPDX outputs record the selected metadata source in document
metadata, including fields such as `nixpkgs:metadata_source_method`,
`nixpkgs:path`, `nixpkgs:rev`, `nixpkgs:flakeref`, `nixpkgs:version`, and
`nixpkgs:message`.
