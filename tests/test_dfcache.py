#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for dataframe cache handling."""

import errno
import os

import pandas as pd
from pandas.testing import assert_frame_equal

from sbomnix.dfcache import LockedDfCache


def test_locked_dfcache_set_avoids_cross_device_rename(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", (tmp_path / "xdg").as_posix())

    def fail_rename(*_args):
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    monkeypatch.setattr(os, "rename", fail_rename)

    cache = LockedDfCache()
    df = pd.DataFrame(
        {
            "product": ["openssl"],
            "vendor": ["openssl_project"],
        }
    )

    cache.set("https://example.invalid/cpes.csv", df, ttl=60)

    assert_frame_equal(cache.get("https://example.invalid/cpes.csv"), df)


def test_locked_dfcache_set_metadata_works_with_standard_cache_operations(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("XDG_CACHE_HOME", (tmp_path / "xdg").as_posix())

    cache = LockedDfCache()
    key = "https://example.invalid/metadata.csv"
    df = pd.DataFrame({"package": ["openssl"], "version": ["3.0.0"]})
    updated_df = pd.DataFrame({"package": ["openssl"], "version": ["3.0.1"]})

    cache_key = cache.set(key, df, ttl=60)
    assert cache.set(key, updated_df, ttl=60) == cache_key
    assert cache.touch(key) == cache_key
    assert_frame_equal(cache.get(key), updated_df)

    assert cache.delete(key) == cache_key
    assert cache.get(key) is None
