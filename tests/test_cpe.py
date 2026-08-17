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


def test_cpe_disabled_returns_empty_string():
    generated = cpe.CPE(include_cpe=False).generate("openssl", "3.0.0")

    assert generated == ""


def test_cpe_uses_canonical_product_identifiers(monkeypatch):
    monkeypatch.setattr(
        cpe,
        "LockedDfCache",
        lambda: FakeCache(pd.DataFrame({"product": ["openssl"], "vendor": [""]})),
    )

    generator = cpe.CPE()
    # Each identity is restated independently of _CPE_OVERRIDES on purpose:
    # every entry was established by checking which identity the vulnerability
    # databases actually carry data for, so an edit to the table has to fail
    # here rather than be mirrored into the expectation. Do not derive this
    # mapping from the table.
    identities = {
        "brave": "a:brave:browser",
        "brave-browser": "a:brave:browser",
        "cairo": "a:cairographics:cairo",
        "cjson": "a:davegamble:cjson",
        "curl": "a:haxx:curl",
        "dhcpcd": "a:dhcpcd_project:dhcpcd",
        "firefox-bin": "a:mozilla:firefox",
        "firefox-esr": "a:mozilla:firefox_esr",
        "gawk": "a:fossies:gawk",
        "gcc": "a:gnu:gcc",
        "glibc": "a:gnu:glibc",
        "google-chrome": "a:google:chrome",
        "google-chrome-beta": "a:google:chrome",
        "google-chrome-dev": "a:google:chrome",
        "gzip": "a:gnu:gzip",
        "jq": "a:jqlang:jq",
        "libcap": "a:libcap_project:libcap",
        "libsndfile": "a:libsndfile_project:libsndfile",
        "linux": "o:linux:linux_kernel",
        "microsoft-edge": "a:microsoft:edge_chromium",
        "patch": "a:gnu:patch",
        "python3": "a:python:python",
        "tor-browser": "a:torproject:tor_browser",
        "unbound": "a:nlnetlabs:unbound",
        "unzip": "a:unzip_project:unzip",
        "wget": "a:gnu:wget",
        "xdg-utils": "a:freedesktop:xdg-utils",
        "xwayland": "a:x.org:xwayland",
    }

    assert identities.keys() == cpe._CPE_OVERRIDES.keys()
    assert {name: generator.generate(name, "1.2.3") for name in identities} == {
        name: f"cpe:2.3:{identity}:1.2.3:*:*:*:*:*:*:*"
        for name, identity in identities.items()
    }
