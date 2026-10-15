#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Generate and scan SBOMs of this app with Syft and Grype (https://github.com/anchore/syft, /grype).
#   scripts/make-sbom.sh            # writes sbom/*.json
#   FAIL_ON=high scripts/make-sbom.sh   # exit non-zero if Grype finds >= high (for CI)
# The Python dependency SBOM needs the project's virtualenv at .venv (pip install -e .).
set -euo pipefail
cd "$(dirname "$0")/.."
command -v syft >/dev/null || { echo "syft not found: see https://github.com/anchore/syft#installation" >&2; exit 1; }
command -v grype >/dev/null || { echo "grype not found: see https://github.com/anchore/grype#installation" >&2; exit 1; }
VERSION=$(cat VERSION)
mkdir -p sbom

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
