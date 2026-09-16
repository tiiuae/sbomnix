#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "usage: $0 {fast|full|live}" >&2
  exit 2
}

lane="${1:-}"
marker_expr=""
coverage=false
pytest_args=()

case "$lane" in
  fast)
    marker_expr="not slow and not network"
    pytest_args+=(-x -n auto -v --durations=10)
    ;;
  full)
    marker_expr="not network"
    coverage=true
    pytest_args+=(-x -n auto -v --durations=20)
    ;;
  live)
    marker_expr="network"
    pytest_args+=(-v -rs --durations=20)
    ;;
  *)
    usage
    ;;
esac

if $coverage; then
  pytest_args+=(
    --cov=src
    --cov-report=term-missing
    --cov-report=xml
  )
fi

if [ -n "$marker_expr" ]; then
  pytest_args+=(-m "$marker_expr")
fi

pytest "${pytest_args[@]}" tests/
