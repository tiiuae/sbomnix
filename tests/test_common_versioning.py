#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-function-docstring

"""Unit tests for shared version and package-name helpers."""

from packaging.version import Version

from common.package_names import nix_to_repology_pkg_name
from common.versioning import parse_version, version_distance


def test_parse_version_normalizes_suffixes():
    parsed = parse_version("openssl-3.0p1")

    assert parsed == Version("3.0+1")


def test_version_distance_handles_identical_and_invalid_versions():
    assert version_distance("1.2.3", "1.2.3") == 1.0
    assert version_distance("release", "1.2.3") == 0.0


def test_nix_to_repology_pkg_name_handles_prefixes_and_special_cases():
    assert nix_to_repology_pkg_name("python311-requests") == "python:requests"
    assert nix_to_repology_pkg_name("ruby-rake") == "ruby:rake"
    assert nix_to_repology_pkg_name("python3") == "python"
    assert nix_to_repology_pkg_name("libtiff") == "tiff"
