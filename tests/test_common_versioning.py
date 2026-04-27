#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-function-docstring

"""Unit tests for shared version and package-name helpers."""

import pytest
from hypothesis import example, given
from hypothesis import strategies as st
from packaging.version import Version

from common.package_names import nix_to_repology_pkg_name
from common.versioning import number_distance, parse_version, version_distance

NON_NEGATIVE_NUMBERS = st.one_of(
    st.integers(min_value=0, max_value=10**18),
    st.floats(min_value=0.0, allow_nan=False, allow_infinity=False),
)
NEGATIVE_NUMBERS = st.one_of(
    st.integers(max_value=-1),
    st.floats(max_value=-0.001, allow_nan=False, allow_infinity=False),
)

VERSION_TEXT = st.text(max_size=120)


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (0, 0, 1.0),
        (0, 1, 0.5),
        (-1, 1, 0.0),
    ],
)
def test_number_distance_documents_edge_cases(left, right, expected):
    assert number_distance(left, right) == expected


@given(NON_NEGATIVE_NUMBERS, NON_NEGATIVE_NUMBERS)
@example(0, 0)
@example(0, 1)
def test_number_distance_is_symmetric_for_non_negative_numbers(left, right):
    assert number_distance(left, right) == number_distance(right, left)


@given(NON_NEGATIVE_NUMBERS, NON_NEGATIVE_NUMBERS)
@example(0, 0)
@example(0, 1)
def test_number_distance_is_bounded_for_non_negative_numbers(left, right):
    result = number_distance(left, right)

    assert 0.0 <= result <= 1.0


@given(NON_NEGATIVE_NUMBERS)
@example(0)
def test_number_distance_identity_for_non_negative_numbers(value):
    assert number_distance(value, value) == 1.0


@given(NEGATIVE_NUMBERS, NON_NEGATIVE_NUMBERS)
def test_number_distance_returns_zero_for_negative_arguments(negative, value):
    assert number_distance(negative, value) == 0.0
    assert number_distance(value, negative) == 0.0


def test_parse_version_normalizes_suffixes():
    parsed = parse_version("openssl-3.0p1")

    assert parsed == Version("3.0+1")


@given(VERSION_TEXT)
def test_parse_version_never_raises_for_text(value):
    parse_version(value)


@given(VERSION_TEXT)
def test_parse_version_is_idempotent_after_string_roundtrip(value):
    parsed = parse_version(value)

    if parsed is not None:
        assert parse_version(str(parsed)) == parsed


def test_version_distance_handles_identical_and_invalid_versions():
    assert version_distance("1.2.3", "1.2.3") == 1.0
    assert version_distance("release", "1.2.3") == 0.0


@given(VERSION_TEXT, VERSION_TEXT)
def test_version_distance_is_bounded_for_text(left, right):
    result = version_distance(left, right)

    assert 0.0 <= result <= 1.0


def test_nix_to_repology_pkg_name_handles_prefixes_and_special_cases():
    assert nix_to_repology_pkg_name("python311-requests") == "python:requests"
    assert nix_to_repology_pkg_name("ruby-rake") == "ruby:rake"
    assert nix_to_repology_pkg_name("python3") == "python"
    assert nix_to_repology_pkg_name("libtiff") == "tiff"
