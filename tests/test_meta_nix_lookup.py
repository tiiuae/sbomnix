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
  - underscore-major-version fallback (attr name embeds major version)
  - dot→dash fallback (dot in pname maps to dash in attr)
  - plus→"plus" fallback (+ sign in pname)
  - dot-in-pname pname extraction ("test.dot-1.0" → pname "test.dot")
  - ruby prefix extraction ("ruby3.3-kramdown-2.4.0" → pname "kramdown")
  - language-subset suffix strip ("python3.13-gyp-unstable-..." → "gyp")
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


def _description(result: dict, name: str) -> str:
    """Return description for *name* in the result dict."""
    return result.get(name, {}).get("meta", {}).get("description", "")


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


def test_underscore_major_version_fallback():
    """Store name "libsoup-3.6.6": pname "libsoup", attr "libsoup_3"."""
    result = _run_meta_nix(["libsoup-3.6.6"])
    assert _license(result, "libsoup-3.6.6") == "Apache-2.0", (
        'underscore-major fallback should find libsoup_3 via pname + "_" + major'
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


def test_leading_digit_pname_fallback():
    """Store name "3proxy-0.9.6": pname "3proxy", attr "_3proxy"."""
    result = _run_meta_nix(["3proxy-0.9.6"])
    assert _license(result, "3proxy-0.9.6") == "BSD-2-Clause", (
        'digit-leading pnames should try an underscore-prefixed attr like "_3proxy"'
    )


def test_ruby_prefix_extraction_uses_ruby_packages():
    """Store name "ruby3.3-kramdown-2.4.0" should extract pname "kramdown"."""
    result = _run_meta_nix(["ruby3.3-kramdown-2.4.0"])
    assert _license(result, "ruby3.3-kramdown-2.4.0") == "Apache-2.0", (
        "mRuby should extract kramdown and search rubyPackages first"
    )
    assert result.get("ruby3.3-kramdown-2.4.0", {}).get("pname") == "kramdown"


def test_language_subset_suffix_strip_uses_prefixed_package_set():
    """Store name "python3.13-gyp-unstable-..." should strip to python3Packages.gyp."""
    result = _run_meta_nix(["python3.13-gyp-unstable-2024-02-07"])
    assert _license(result, "python3.13-gyp-unstable-2024-02-07") == "Apache-2.0", (
        "suffix stripping should search python3Packages for prefixed python names"
    )
    assert result.get("python3.13-gyp-unstable-2024-02-07", {}).get("pname") == "gyp"


def test_perl_dash_removed_lookup_runs_before_suffix_strip():
    """Perl CPAN dash-removal must win before suffix stripping can hit the wrong module."""
    result = _run_meta_nix(
        [
            "perl5.42.0-CGI-Fast-2.16",
            "perl5.42.0-FCGI-ProcManager-0.28",
            "perl5.42.0-Encode-Locale-1.05",
            "perl5.42.0-IO-HTML-1.004",
        ]
    )

    assert _license(result, "perl5.42.0-CGI-Fast-2.16") == "Correct-CGI-Fast"
    assert _license(result, "perl5.42.0-FCGI-ProcManager-0.28") == (
        "Correct-FCGI-ProcManager"
    )
    assert (
        _description(result, "perl5.42.0-Encode-Locale-1.05")
        == "Fixture: correct Perl dash-removed lookup for Encode-Locale"
    )
    assert (
        _description(result, "perl5.42.0-IO-HTML-1.004")
        == "Fixture: correct Perl dash-removed lookup for IO-HTML"
    )


def test_patch_files_are_not_matched_as_packages():
    """Build-time patch files must not resolve to unrelated nixpkgs package metadata."""
    result = _run_meta_nix(
        [
            "CVE-2019-13232-1.patch",
            "fix-static.patch.gz",
            "upstream.diff",
            "series.diff.xz",
            "fixup.diff?id=deadbeef",
        ]
    )

    assert "CVE-2019-13232-1.patch" not in result
    assert "fix-static.patch.gz" not in result
    assert "upstream.diff" not in result
    assert "series.diff.xz" not in result
    assert "fixup.diff?id=deadbeef" not in result


def test_source_artifact_files_are_not_matched_as_packages():
    """Source-like file artifacts must not receive exact nixpkgs package metadata."""
    result = _run_meta_nix(
        [
            "Python-3.14.2.tar.xz",
            "CUnit-2.1-3.tar.bz2",
            "wheelhouse.whl",
            "package.cabal",
            "archive.zip",
            "rubygem.gem",
        ]
    )

    assert "Python-3.14.2.tar.xz" not in result
    assert "CUnit-2.1-3.tar.bz2" not in result
    assert "wheelhouse.whl" not in result
    assert "package.cabal" not in result
    assert "archive.zip" not in result
    assert "rubygem.gem" not in result


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


def test_exact_name_match_beats_cross_set_pname_collision():
    """An exact canonical drv.name match should beat same-pname cross-set collisions."""
    result = _run_meta_nix(["hello-2.12.3", "hello-1.0.0.2"])
    top_level = result["hello-2.12.3"]
    haskell = result["hello-1.0.0.2"]

    assert top_level["ambiguous"] is False
    assert top_level["preciseNeeded"] is False
    assert top_level["meta"]["description"] == "Fixture: top-level hello"
    assert top_level["meta"]["license"]["shortName"] == "Top-Level-Hello"

    assert haskell["ambiguous"] is False
    assert haskell["preciseNeeded"] is False
    assert haskell["meta"]["description"] == "Fixture: haskell hello"
    assert haskell["meta"]["license"]["shortName"] == "Haskell-Hello"


def test_split_output_name_beats_cross_set_pname_collision():
    """Known split outputs should narrow candidates back to the owning derivation."""
    result = _run_meta_nix(["split-demo-1.0-doc"])
    entry = result["split-demo-1.0-doc"]

    assert entry["ambiguous"] is False
    assert entry["preciseNeeded"] is False
    assert entry["meta"]["description"] == "Fixture: top-level split-demo"
    assert entry["meta"]["license"]["shortName"] == "Top-Level-Split-Demo"


def test_unprefixed_name_marks_cross_set_name_collisions_as_ambiguous():
    """Names present in both pkgs and haskellPackages should be flagged."""
    result = _run_meta_nix(["cornelis-0.2.0.1"])
    entry = result["cornelis-0.2.0.1"]

    assert entry["ambiguous"] is True
    assert entry["preciseNeeded"] is True
    assert entry["meta"]["description"] == "Fixture: top-level cornelis"
    assert entry["meta"]["license"]["shortName"] == "Top-Level-Cornelis"


def test_metadata_equivalent_cross_set_collision_skips_precise_flag():
    """Identical exported metadata should not be treated as a guessing risk."""
    result = _run_meta_nix(["same-meta-1.0"])
    entry = result["same-meta-1.0"]

    assert entry["ambiguous"] is True
    assert entry["preciseNeeded"] is False
    assert entry["meta"]["description"] == "Fixture: same metadata collision"
