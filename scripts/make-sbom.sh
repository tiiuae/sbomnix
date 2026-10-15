#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Generate and scan SBOMs of this app with Syft and Grype (https://github.com/anchore/syft, /grype).
#   scripts/make-sbom.sh                 # writes sbom/*.json for the working tree
#   scripts/make-sbom.sh --ref v1.9.0    # SBOM of any earlier version (tag, branch or commit); output sbom/<name>-<ref>.*
#   FAIL_ON=high scripts/make-sbom.sh    # exit non-zero if Grype finds >= high (for CI)
# The Python dependency SBOM needs the project's virtualenv at .venv (pip install -e .).
set -euo pipefail
cd "$(dirname "$0")/.."
command -v syft >/dev/null || { echo "syft not found: see https://github.com/anchore/syft#installation" >&2; exit 1; }
command -v grype >/dev/null || { echo "grype not found: see https://github.com/anchore/grype#installation" >&2; exit 1; }
REF=""
if [ "${1:-}" = "--ref" ]; then
  REF="${2:-}"; [ -n "$REF" ] || { echo "--ref needs a git tag, branch or commit" >&2; exit 2; }
  git rev-parse --verify --quiet "$REF^{commit}" >/dev/null || { echo "unknown git ref: $REF" >&2; exit 2; }
elif [ $# -gt 0 ]; then
  echo "usage: $0 [--ref GIT_REF]" >&2; exit 2
fi
mkdir -p sbom

if [ -n "$REF" ]; then
  # an earlier version: check it out into a temporary worktree (the working tree is not touched), inventory that
  SAFE=$(printf '%s' "$REF" | tr -c 'A-Za-z0-9._-' '_')
  WT=$(mktemp -d)
  trap 'git worktree remove --force "$WT" >/dev/null 2>&1 || true; rm -rf "$WT"' EXIT
  git worktree add --detach "$WT" "$REF" >/dev/null 2>&1
  VERSION=$(cat "$WT/VERSION" 2>/dev/null || echo "$REF")
  ( cd "$WT" && syft dir:. --source-name sbomnix-explorer --source-version "$VERSION" --exclude './.git/**' \
      -o cyclonedx-json="$OLDPWD/sbom/sbomnix-explorer-$SAFE.cdx.json" -o spdx-json="$OLDPWD/sbom/sbomnix-explorer-$SAFE.spdx.json" )
  OUT="sbom/sbomnix-explorer-$SAFE.cdx.json"
  grype "sbom:$OUT" -o json > "${OUT%.cdx.json}.grype.json" ${FAIL_ON:+--fail-on "$FAIL_ON"}
  python3 -c "import json,sys;print(sys.argv[1],'->',len(json.load(open(sys.argv[1]))['components']),'components,',len(json.load(open(sys.argv[2]))['matches']),'matches')" "$OUT" "${OUT%.cdx.json}.grype.json"
  exit 0
fi

VERSION=$(cat VERSION)

# 1. the repository: workflows' GitHub Actions + the sbomnix package itself
syft dir:. --source-name sbomnix-explorer --source-version "$VERSION" \
  --exclude './.venv/**' --exclude './.git/**' --exclude './sbom/**' \
  -o cyclonedx-json=sbom/sbomnix-explorer.cdx.json -o spdx-json=sbom/sbomnix-explorer.spdx.json

# 2. the Python dependencies as installed (pyproject.toml has no lockfile, so this is the pinned view)
if [ -d .venv ]; then
  syft dir:.venv --source-name sbomnix-python-deps --source-version "$VERSION" \
    -o cyclonedx-json=sbom/sbomnix-python-deps.cdx.json
fi

# 3. scan every SBOM; re-run whenever the Grype DB updates, no rebuild needed
for f in sbom/*.cdx.json; do
  grype "sbom:$f" -o json > "${f%.cdx.json}.grype.json" ${FAIL_ON:+--fail-on "$FAIL_ON"}
  python3 -c "import json,sys;print(sys.argv[1],'->',len(json.load(open(sys.argv[2]))['matches']),'matches')" "$f" "${f%.cdx.json}.grype.json"
done
