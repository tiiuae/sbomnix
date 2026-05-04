#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for meta.nix pname lookup logic using the local fixture package set.

These tests call `nix eval` against tests/resources/nixmeta-package-set.nix,
which is a tiny self-contained fake nixpkgs (no import <nixpkgs> required).
They are fast (no network, no builds) and exercise the lookup paths in meta.nix:
  - exact pname lookup
  - suffix-strip cascade (restricted to pkgs)
  - lowercase fallback (case-divergent pnames)
  - dash-removed fallback (attr name has no dashes)
  - digit-suffix fallback (attr name has trailing digit)
  - dot→dash fallback (dot in pname maps to dash in attr)
  - plus→"plus" fallback (+ sign in pname)
  - dot-in-pname pname extraction ("test.dot-1.0" → pname "test.dot")
"""

import json
import subprocess
from pathlib import Path

REPOROOT = Path(__file__).resolve().parent.parent
META_NIX = REPOROOT / "src" / "nixmeta" / "meta.nix"
PKGSET_NIX = REPOROOT / "tests" / "resources" / "nixmeta-package-set.nix"


def _run_meta_nix(names: list[str]) -> dict:
    """Evaluate meta.nix against the fixture package set and return the result."""
    names_nix = " ".join(f'"{n}"' for n in names)
    expr = (
        f"let f = import {META_NIX}; "
        f"pkgs = import {PKGSET_NIX} {{}}; "
        f"in f {{ inherit pkgs; names = [{names_nix}]; }}"
    )
    ret = subprocess.run(
        ["nix", "eval", "--json", "--impure", "--expr", expr],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ret.returncode == 0, f"nix eval failed:\n{ret.stderr}"
    return json.loads(ret.stdout)


def _license(result: dict, name: str) -> str:
    """Return shortName of the license for *name* in the result dict."""
    meta = result.get(name, {}).get("meta", {})
    lic = meta.get("license", {})
    return lic.get("shortName", "")


def test_exact_pname_lookup():
    """Standard packages with matching pname and attr name are found."""
    result = _run_meta_nix(["sbomnix-meta-first-1.0", "sbomnix-meta-second-2.0"])
    assert _license(result, "sbomnix-meta-first-1.0") == "Apache-2.0"
    assert _license(result, "sbomnix-meta-second-2.0") == "Apache-2.0"


def test_lowercase_fallback():
    """Store name "TestCaseDiverge-1.0": pname "TestCaseDiverge", attr "testcasediverge"."""
    result = _run_meta_nix(["TestCaseDiverge-1.0"])
    assert _license(result, "TestCaseDiverge-1.0") == "Apache-2.0", (
        "rLower should find testcasediverge via toLower('TestCaseDiverge')"
    )


def test_dash_removed_fallback():
    """Store name "test-dashremoved-1.0": pname "test-dashremoved", attr "testdashremoved"."""
    result = _run_meta_nix(["test-dashremoved-1.0"])
    assert _license(result, "test-dashremoved-1.0") == "Apache-2.0", (
        'rNoDash should find testdashremoved via replaceStrings ["-"] [""]'
    )


def test_digit_suffix_fallback():
    """Store name "test-digitsuffix-1.0": pname "test-digitsuffix", attr "test-digitsuffix2"."""
    result = _run_meta_nix(["test-digitsuffix-1.0"])
    assert _license(result, "test-digitsuffix-1.0") == "Apache-2.0", (
        "rDigit should find test-digitsuffix2 by trying pname + '2'"
    )


def test_dot_to_dash_fallback():
    """Store name "test.dot-1.0": pname "test.dot", attr "test-dot"."""
    result = _run_meta_nix(["test.dot-1.0"])
    assert _license(result, "test.dot-1.0") == "Apache-2.0", (
        'rDotDash should find test-dot via replaceStrings ["."] ["-"]'
    )


def test_plus_to_plus_word_fallback():
    """Store name "test86+-1.0": pname "test86+", attr "test86plus"."""
    result = _run_meta_nix(["test86+-1.0"])
    assert _license(result, "test86+-1.0") == "Apache-2.0", (
        'rPlus should find test86plus via replaceStrings ["+"] ["plus"]'
    )


def test_dot_in_pname_extraction():
    """Store name "test.dot-1.0": _pnamePat allows dots, extracting pname "test.dot"."""
    result = _run_meta_nix(["test.dot-1.0"])
    assert result.get("test.dot-1.0", {}).get("pname") == "test.dot", (
        "_pnamePat should allow dots; test.dot-1.0 should extract pname 'test.dot'"
    )


def test_unknown_package_returns_no_entry():
    """A name with no nixpkgs match produces no result entry."""
    result = _run_meta_nix(["completely-unknown-package-999.0"])
    assert "completely-unknown-package-999.0" not in result
