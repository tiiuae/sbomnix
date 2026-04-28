#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for CPE generation."""

import pandas as pd

from sbomnix import cpe


class FakeCache:
    def __init__(self, df):
        self.df = df

    def get(self, _url):
        return self.df

    def set(self, *_args, **_kwargs):
        raise AssertionError("cache set should not be called for populated data")


def test_cpe_uses_indexed_unique_product_vendor(monkeypatch):
    monkeypatch.setattr(
        cpe,
        "LockedDfCache",
        lambda: FakeCache(
            pd.DataFrame(
                {
                    "product": ["openssl", "curl"],
                    "vendor": ["openssl_project", "curl_project"],
                }
            )
        ),
    )

    generated = cpe.CPE().generate("openssl", "3.0.0")

    assert generated == "cpe:2.3:a:openssl_project:openssl:3.0.0:*:*:*:*:*:*:*"


def test_cpe_ambiguous_product_falls_back_to_product_name(monkeypatch):
    monkeypatch.setattr(
        cpe,
        "LockedDfCache",
        lambda: FakeCache(
            pd.DataFrame(
                {
                    "product": ["openssl", "openssl"],
                    "vendor": ["first_vendor", "second_vendor"],
                }
            )
        ),
    )

    generated = cpe.CPE().generate("openssl", "3.0.0")

    assert generated == "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"
