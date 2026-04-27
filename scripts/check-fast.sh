#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

nix fmt
nix --extra-experimental-features 'flakes nix-command' flake check --no-build
nix develop --command ./scripts/run-pytest-lane.sh fast
