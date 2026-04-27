#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "usage: $0 {fast|full}" >&2
  exit 2
}

lane="${1:-}"
case "$lane" in
  fast)
    marker_expr="not slow and not network"
    ;;
  full)
    marker_expr=""
    ;;
  *)
    usage
    ;;
esac

pytest_args=(
  -n auto
  -vx
  --durations=20
)

if [ -n "$marker_expr" ]; then
  pytest_args+=(-m "$marker_expr")
fi

pytest "${pytest_args[@]}" tests/
