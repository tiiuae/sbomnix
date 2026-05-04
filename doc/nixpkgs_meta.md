<!--
SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# nixpkgs metadata lookup

`sbomnix` enriches SBOMs with nixpkgs metadata (license, homepage,
description, maintainers) by querying the nixpkgs attribute tree for
each package in the SBOM.  This document describes how that lookup
works.

## Why names, not store paths

Every package in a Nix build is stored under a path such as:

```
/nix/store/9xfad3b5z4k...-hello-2.12.3/
```

The hash prefix (`9xfad3b5z4k...`) is a content hash of the
derivation's inputs.  It cannot be predicted from the nixpkgs source
tree without evaluating every derivation, which is prohibitively
expensive.

The **name** portion (`hello-2.12.3`) encodes the `pname` and
`version` that nixpkgs assigned to the package.  Since `meta.nix` is
evaluated against the exact same nixpkgs that produced the SBOM, the
name is a strong hint toward the correct derivation.  The lookup is
heuristic: it strips version suffixes with regex patterns, reorders
search sets to prefer language-specific package sets when a language
prefix is detected, and applies naming-convention fallbacks for packages
whose nixpkgs attribute name diverges from the pname.  Pname collisions
across package sets are reduced rather than ruled out by construction.
The internal SBOM component table carries both the full `store_path` and
its `name`; the lookup uses `name` because the full path offers no better
reverse-lookup key, it would just need to be parsed back into the same
name suffix.

## Lookup pipeline

### 1. Input: store-path names

The SBOM already contains the name component of each store path.
`NixMetaScanner.scan_store_names(names, pkgs_expr=...)` receives this
list and passes it in batches to `meta.nix`.

### 2. pname extraction (`_pnameFromName`)

`meta.nix` extracts the pname from each name using a cascade of regex
patterns that handle the naming conventions nixpkgs uses:

| Input name | Extracted pname |
|---|---|
| `hello-2.12.3` | `hello` |
| `alsa-utils-1.2.14` | `alsa-utils` |
| `glibc-2.42-51` | `glibc` (stops at first digit segment) |
| `python3.13-requests-2.31.0` | `requests` |
| `perl5.40-XML-Simple-1.0` | `XML-Simple` (2-part version) |
| `perl5.42.0-XML-Simple-2.25` | `XML-Simple` (3-part version) |
| `3proxy-0.9.6` | `3proxy` (digit-leading pname) |
| `python3.13-asn1crypto-1.5.1-unstable-2023-11-03` | `asn1crypto` |

The pattern stops at the first dash-digit boundary so that names like
`glibc-2.42-51` do not produce `glibc-2.42` as the pname.

### 3. Search-set selection (`_prefixedSearchSets`)

To avoid false positives from pname collisions between the top-level
and language-specific package sets, the search order is adjusted based
on the language prefix of the store-path name:

- `python3.X-*`: prefer `python3Packages` before `pkgs`
- `perl5.X.Y-*`: prefer `perlPackages` before `pkgs`
- `rubyX.Y-*`: prefer `rubyPackages` before `pkgs`
- All others: `pkgs`, then haskellPackages, python3Packages, perlPackages,
  rubyPackages, ocamlPackages, rPackages, nodePackages, qt6

### 4. Attribute lookup with suffix-strip cascade

The extracted pname is looked up in each search set in order.  If no
match is found, one and then two trailing dash-word suffixes are
stripped (`bash-interactive` to `bash`, `ghostscript-with-X` to
`ghostscript-with` to `ghostscript`) and the lookup is retried.

### 5. Naming-convention fallbacks

Some packages have nixpkgs attribute names that differ from their
pname. When direct lookup and suffix stripping do not find a match,
`meta.nix` applies a sequence of heuristic normalizations for common
nixpkgs naming divergences.

These heuristics are intended to improve coverage while keeping false
positives low. The exact list and ordering are implementation details
and may evolve as the lookup logic improves, but they include patterns
such as:

- Perl CPAN names with dashes removed, for example
  `Authen-SASL` -> `perlPackages.AuthenSASL`
- C++ libraries where `++` maps to `xx`, for example
  `libsigc++` -> `pkgs.libsigcxx`
- names normalized by punctuation or case changes, such as hyphen to
  underscore, lowercase conversion, or dot to dash
- attrs that encode version information in the attribute name, such as
  `libsoup-3.6.6` -> `pkgs.libsoup_3`
- a small number of targeted special cases, such as `gtk+` -> `pkgs.gtk2`
  and `webkitgtk-2.52.2+abi=4.1` -> `pkgs.webkitgtk_4_1`

The lookup order is tuned to prefer the most plausible match for the
current package-set context rather than being a stable public API.

### 6. Metadata extraction

Once a derivation is found, `filteredMeta` projects the JSON-safe
subset of its `.meta` attribute: `description`, `homepage`, `unfree`,
`position`, `license`, and `maintainers`.

## Determining the right `pkgs`

`meta.nix` requires a `pkgs` argument pointing to the exact nixpkgs
used to build the target.  `NixpkgsMetaSourceResolver` resolves this
through one rule for NixOS system targets and another for general flake
targets.

### NixOS configuration targets

This rule applies only to flakerefs of the form:

```text
<flake>#nixosConfigurations.NAME.config.system.build.toplevel
```

For those targets, the resolver probes
`LOCKED_FLAKE#nixosConfigurations.NAME.pkgs.path`. If that succeeds,
the `pkgs` expression becomes:

```nix
(builtins.getFlake "LOCKED_FLAKE").nixosConfigurations.NAME.pkgs
```

This picks up the exact nixpkgs instance the NixOS configuration uses,
which may differ from the flake's top-level `inputs.nixpkgs`.  If the
probe fails (configuration exists but does not expose `pkgs`),
`pkgs_expression` is left unset and the scan is skipped with a
warning. Plain flakerefs such as `#nixosConfigurations.NAME` do not use
this NixOS-specific resolution rule; they fall through to the general flake logic
described below.

### Other flake targets

For all other flakerefs, `LOCKED_FLAKE` is the `narHash`-pinned store
path obtained from `nix flake metadata`.  The resolver then tries the
following steps in order:

1. **Target flake is nixpkgs itself** (e.g. `nixpkgs#hello`):

   ```nix
   import (builtins.getFlake "LOCKED_FLAKE") {}
   ```

2. **Lock-graph resolution** — the resolver reads the lock graph from
   `nix flake metadata --json` and looks for a pinned nixpkgs input.
   It first checks `locks.nodes[locks.root].inputs.nixpkgs`.  If that
   value is a string, the named node is used directly; if it is an
   override-chain list, the last element is treated as the resolved
   nixpkgs node.  If the key is absent, the resolver falls back to a
   single unambiguous node whose locked object positively identifies
   nixpkgs: `github` nodes via `locked.repo == "nixpkgs"` and `git` or
   `tarball` nodes via a URL path segment named `nixpkgs`. Path inputs
   are only accepted when they are referenced explicitly through
   `root.inputs.nixpkgs`; a path node that merely looks nixpkgs-like by
   name is not guessed. When exactly one candidate is found, the `pkgs`
   expression is built directly from the locked object. When the locked
   nixpkgs input carries a `dir` field, the emitted flakeref preserves
   it so subflake inputs keep pointing at the locked subdirectory.
   Supported lock types and the expressions they produce:

   | Lock type | Expression |
   |---|---|
   | `github` | `import (builtins.getFlake "github:OWNER/REPO?rev=REV&narHash=HASH[&dir=SUBDIR]") {}` |
   | `git` | `import (builtins.getFlake "git+URL?ref=REF&rev=REV[&dir=SUBDIR]") {}` |
   | `tarball` | `import (builtins.getFlake "URL?narHash=HASH[&dir=SUBDIR]") {}` |
   | `path` (store path) | `import "/nix/store/…[/SUBDIR]" {}` |

   When the lock graph contains multiple nixpkgs-like nodes and none is
   identified as the explicit root input, the resolver does not guess
   and falls through to step 3.

3. **Direct import fallback** — used when the lock-graph step finds no
   unambiguous nixpkgs input:

   ```nix
   import (builtins.getFlake "LOCKED_FLAKE") {}
   ```

   This will fail for flakes that do not export a valid nixpkgs, in
   which case the scan is skipped and a message is recorded in the SBOM
   source description.  When no stable lock can be determined at all,
   the scan is also skipped.

Sub-package sets (haskellPackages, python3Packages, etc.) are loaded
with `builtins.tryEval` so that sets missing or broken in a given
nixpkgs revision are silently skipped rather than aborting the scan.

## Metadata source export

When `sbomnix` resolves a nixpkgs metadata source, it exports that
selection into the generated SBOM:

- CycloneDX stores document properties named
  `nixpkgs:metadata_source_method`, `nixpkgs:path`, `nixpkgs:rev`,
  `nixpkgs:flakeref`, `nixpkgs:version`, and `nixpkgs:message`
- SPDX stores the same fields as a compact line in the document comment

This makes it possible to tell after the fact which nixpkgs source was
used for metadata enrichment, or why enrichment was skipped.
