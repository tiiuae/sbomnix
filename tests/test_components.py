#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for SBOM component dataframe helpers."""

from sbomnix import components as sbomnix_components


class FakeDrv:
    """Minimal derivation double for component dataframe tests."""

    def __init__(self, store_path, name):
        self.store_path = store_path
        self.name = name
        self.outputs = []
        self.cpe_set = False

    def set_cpe(self, _generator):
        self.cpe_set = True

    def to_dict(self):
        return {
            "store_path": self.store_path,
            "name": self.name,
            "outputs": self.outputs,
            "cpe_set": self.cpe_set,
        }


def test_recursive_derivations_to_dataframe_skips_missing_paths():
    derivations = {
        "/nix/store/first.drv": FakeDrv("/nix/store/first.drv", "first"),
        "/nix/store/second.drv": FakeDrv("/nix/store/second.drv", "second"),
    }

    # Keep the test focused on component assembly without loading CPE data.
    df_components = sbomnix_components.recursive_derivations_to_dataframe(
        [
            "/nix/store/missing.drv",
            "/nix/store/second.drv",
            "/nix/store/first.drv",
        ],
        derivations,
        include_cpe=False,
    )

    assert df_components.to_dict("records") == [
        {
            "store_path": "/nix/store/first.drv",
            "name": "first",
            "outputs": [],
            "cpe_set": True,
        },
        {
            "store_path": "/nix/store/second.drv",
            "name": "second",
            "outputs": [],
            "cpe_set": True,
        },
    ]


def test_runtime_derivations_to_dataframe_filters_outputs_before_loading(monkeypatch):
    load_calls = []

    def fake_load_many(paths, output_paths_by_drv=None):
        load_calls.append((paths, output_paths_by_drv))
        return {
            "/nix/store/first.drv": FakeDrv("/nix/store/first.drv", "first"),
            "/nix/store/second.drv": FakeDrv("/nix/store/second.drv", "second"),
        }

    monkeypatch.setattr(sbomnix_components, "load_many", fake_load_many)

    df_components = sbomnix_components.runtime_derivations_to_dataframe(
        {
            "/nix/store/first-out",
            "/nix/store/second-out",
        },
        {
            "/nix/store/first.drv": {
                "/nix/store/first-out",
                "/nix/store/ignored-first-out",
            },
            "/nix/store/second.drv": {
                "/nix/store/second-out",
            },
            "/nix/store/ignored.drv": {
                "/nix/store/ignored-out",
            },
        },
        include_cpe=False,
    )

    assert load_calls == [
        (
            ["/nix/store/first.drv", "/nix/store/second.drv"],
            {
                "/nix/store/first.drv": {"/nix/store/first-out"},
                "/nix/store/second.drv": {"/nix/store/second-out"},
            },
        )
    ]
    assert df_components["store_path"].to_list() == [
        "/nix/store/first.drv",
        "/nix/store/second.drv",
    ]
