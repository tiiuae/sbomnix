#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

mkdir -p build/

release_target=".#sbomnix"

nix run .#sbomnix -- "$release_target" \
  --cdx=./build/sbom.runtime.cdx.json \
  --spdx=./build/sbom.runtime.spdx.json \
  --csv=./build/sbom.runtime.csv

nix run .#sbomnix -- --buildtime "$release_target" \
  --cdx=./build/sbom.buildtime.cdx.json \
  --spdx=./build/sbom.buildtime.spdx.json \
  --csv=./build/sbom.buildtime.csv

echo
echo "Built release asset:"
ls -la build
