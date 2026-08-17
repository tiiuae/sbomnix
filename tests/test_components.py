#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for SBOM component dataframe helpers."""

from common import columns as cols
from sbomnix import cdx as sbomnix_cdx
from sbomnix import components as sbomnix_components
from sbomnix.artifacts import is_non_package_artifact_name


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

    def fake_load_many(paths, output_paths_by_drv=None, ignore_missing=False):
        load_calls.append((paths, output_paths_by_drv, ignore_missing))
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
            "/nix/store/first-out": {
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
            ["/nix/store/first-out", "/nix/store/second.drv"],
            {
                "/nix/store/first-out": {"/nix/store/first-out"},
                "/nix/store/second.drv": {"/nix/store/second-out"},
            },
            True,
        )
    ]
    assert df_components["store_path"].to_list() == [
        "/nix/store/first.drv",
        "/nix/store/second.drv",
    ]


def test_runtime_derivations_to_dataframe_infers_missing_runtime_components(
    monkeypatch,
):
    linux_out = "/nix/store/11111111111111111111111111111111-linux-7.1.7"
    linux_modules = "/nix/store/22222222222222222222222222222222-linux-7.1.7-modules"
    unstable_out = "/nix/store/33333333333333333333333333333333-foo-unstable-2024-01-01"
    abi_out = "/nix/store/44444444444444444444444444444444-webkitgtk-2.52.5+abi=4.1"
    abi_dev = "/nix/store/55555555555555555555555555555555-webkitgtk-2.52.5+abi=4.1-dev"
    script_out = "/nix/store/66666666666666666666666666666666-stage-2-init.sh"
    dbus_wrapper = "/nix/store/77777777777777777777777777777777-dbus-1"
    dbus_out = "/nix/store/88888888888888888888888888888888-dbus-1.16.2"
    bind_host = "/nix/store/99999999999999999999999999999999-bind-9.20.26-host"
    output_paths_by_load_path = {
        linux_out: {linux_out, linux_modules},
        unstable_out: {unstable_out},
        abi_out: {abi_out, abi_dev},
        script_out: {script_out},
        dbus_wrapper: {dbus_wrapper},
        dbus_out: {dbus_out},
        bind_host: {bind_host},
    }
    output_paths = set().union(*output_paths_by_load_path.values())

    def fake_load_many(paths, output_paths_by_drv=None, ignore_missing=False):
        assert paths == sorted(output_paths_by_load_path)
        assert output_paths_by_drv == output_paths_by_load_path
        assert ignore_missing is True
        return {}

    monkeypatch.setattr(sbomnix_components, "load_many", fake_load_many)

    df_components = sbomnix_components.runtime_derivations_to_dataframe(
        output_paths,
        output_paths_by_load_path,
        include_cpe=False,
    )

    columns = [
        cols.STORE_PATH,
        cols.NAME,
        cols.PNAME,
        cols.VERSION,
        "purl",
        cols.OUTPUTS,
    ]
    assert list(df_components[columns].itertuples(index=False, name=None)) == [
        (
            linux_out,
            "linux-7.1.7",
            "linux",
            "7.1.7",
            "pkg:nix/linux@7.1.7",
            [linux_out, linux_modules],
        ),
        (
            unstable_out,
            "foo-unstable-2024-01-01",
            "foo",
            "unstable-2024-01-01",
            "pkg:nix/foo@unstable-2024-01-01",
            [unstable_out],
        ),
        (
            abi_out,
            "webkitgtk-2.52.5",
            "webkitgtk",
            "2.52.5",
            "pkg:nix/webkitgtk@2.52.5",
            [abi_out, abi_dev],
        ),
        (
            dbus_out,
            "dbus-1.16.2",
            "dbus",
            "1.16.2",
            "pkg:nix/dbus@1.16.2",
            [dbus_out],
        ),
        (
            bind_host,
            "bind-9.20.26",
            "bind",
            "9.20.26",
            "pkg:nix/bind@9.20.26",
            [bind_host],
        ),
    ]
    assert (df_components[cols.CPE] == "").all()
    assert df_components[cols.METADATA_UNAVAILABLE].all()
    cdx_component = sbomnix_cdx._drv_to_cdx_component(
        next(df_components.itertuples(index=False))
    )
    output_properties = [
        prop["value"]
        for prop in cdx_component["properties"]
        if prop["name"] == "nix:output_path"
    ]
    assert output_properties == [linux_out, linux_modules]
    assert "nix:drv_path" not in {prop["name"] for prop in cdx_component["properties"]}


def test_non_package_artifact_names_include_runtime_file_formats():
    names = ("plugin-4-api.hpi", "overlay-5.dts", "package.deb", "package.rpm")

    assert [name for name in names if not is_non_package_artifact_name(name)] == []
