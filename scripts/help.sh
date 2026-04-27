#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cat <<'EOF'
Available helper scripts:

  ./scripts/check-fast.sh      Run local formatter, eval, and fast tests
  ./scripts/check-full.sh      Run formatter, full flake check, and full tests
  ./scripts/run-pytest-lane.sh Run pytest lane: fast or full
  ./scripts/release-asset.sh   Build release SBOM assets into ./build
EOF
