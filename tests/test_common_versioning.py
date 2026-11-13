#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for shared version helpers."""

from hypothesis import given
from hypothesis import strategies as st
from packaging.version import Version

from common.versioning import parse_version

VERSION_TEXT = st.text(max_size=120)


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
