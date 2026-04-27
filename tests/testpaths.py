#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared paths for the test suite."""

from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
RESOURCES_DIR = TESTS_DIR / "resources"
REPOROOT = TESTS_DIR.parent
SRCDIR = REPOROOT / "src"

COMPARE_DEPS = TESTS_DIR / "compare_deps.py"
COMPARE_SBOMS = TESTS_DIR / "compare_sboms.py"

SBOMNIX = SRCDIR / "sbomnix" / "main.py"
NIXGRAPH = SRCDIR / "nixgraph" / "main.py"
NIXMETA = SRCDIR / "nixmeta" / "main.py"
PROVENANCE = SRCDIR / "provenance" / "main.py"
NIX_OUTDATED = SRCDIR / "nixupdate" / "nix_outdated.py"
VULNXSCAN = SRCDIR / "vulnxscan" / "vulnxscan_cli.py"
REPOLOGY_CLI = SRCDIR / "repology" / "repology_cli.py"
