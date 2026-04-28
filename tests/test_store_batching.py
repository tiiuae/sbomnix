#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for batched store and derivation loading."""

import json
from types import SimpleNamespace

from sbomnix import derivation as sbomnix_derivation
from sbomnix import derivers as sbomnix_derivers
from sbomnix import fallback_store as sbomnix_fallback_store


def test_find_derivers_batches_nix_store_queries(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(
            stdout="/nix/store/first.drv\n/nix/store/second.drv\n",
            returncode=0,
        )

    monkeypatch.setattr(sbomnix_derivers, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr("os.path.exists", lambda path: path.endswith(".drv"))

    resolved = sbomnix_derivers.find_derivers(
        ["/nix/store/first", "/nix/store/second"],
        batch_size=50,
    )

    assert resolved == {
        "/nix/store/first": "/nix/store/first.drv",
        "/nix/store/second": "/nix/store/second.drv",
    }
    assert calls == [
        (
            ["nix-store", "-qd", "/nix/store/first", "/nix/store/second"],
            {"raise_on_error": False, "log_error": False},
        )
    ]


def test_load_many_batches_nix_derivation_show_and_preserves_outputs(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "derivations": {
                        "/nix/store/first.drv": {
                            "name": "first",
                            "env": {
                                "name": "first",
                                "pname": "first",
                                "version": "1.0",
                            },
                            "outputs": {
                                "out": {"path": "/nix/store/first-out"},
                            },
                        },
                        "/nix/store/second.drv": {
                            "name": "second",
                            "env": {
                                "name": "second",
                                "pname": "second",
                                "version": "2.0",
                            },
                            "outputs": {
                                "out": {"path": "/nix/store/second-out"},
                            },
                        },
                    },
                    "version": 4,
                }
            ),
            returncode=0,
            stderr="",
        )

    monkeypatch.setattr(sbomnix_derivation, "exec_cmd", fake_exec_cmd)

    loaded = sbomnix_derivation.load_many(
        ["/nix/store/first.drv", "/nix/store/second.drv"],
        output_paths_by_drv={
            "/nix/store/first.drv": {"/nix/store/first-extra-out"},
            "/nix/store/second.drv": {"/nix/store/second-extra-out"},
        },
        batch_size=50,
    )

    assert calls == [
        (
            [
                "nix",
                "derivation",
                "show",
                "/nix/store/first.drv",
                "/nix/store/second.drv",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
            ],
            {},
        )
    ]
    assert loaded["/nix/store/first.drv"].outputs == [
        "/nix/store/first-extra-out",
        "/nix/store/first-out",
    ]
    assert loaded["/nix/store/second.drv"].outputs == [
        "/nix/store/second-extra-out",
        "/nix/store/second-out",
    ]


def test_load_many_supports_output_path_queries(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "derivations": {
                        "/nix/store/canonical.drv": {
                            "name": "first",
                            "env": {
                                "name": "first",
                                "pname": "first",
                                "version": "1.0",
                            },
                            "outputs": {
                                "out": {"path": "/nix/store/first-out"},
                                "dev": {"path": "/nix/store/first-dev"},
                            },
                        },
                    },
                    "version": 4,
                }
            ),
            returncode=0,
            stderr="",
        )

    monkeypatch.setattr(sbomnix_derivation, "exec_cmd", fake_exec_cmd)

    loaded = sbomnix_derivation.load_many(
        ["/nix/store/first-out"],
        output_paths_by_drv={
            "/nix/store/first-out": {"/nix/store/first-out"},
        },
        batch_size=50,
    )

    assert calls == [
        (
            [
                "nix",
                "derivation",
                "show",
                "/nix/store/first-out",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
            ],
            {},
        )
    ]
    assert list(loaded) == ["/nix/store/canonical.drv"]
    assert loaded["/nix/store/canonical.drv"].store_path == "/nix/store/canonical.drv"
    assert loaded["/nix/store/canonical.drv"].outputs == [
        "/nix/store/first-dev",
        "/nix/store/first-out",
    ]


def test_load_many_maps_output_queries_from_derivation_env(monkeypatch):
    def fake_exec_cmd(cmd, **kwargs):
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "derivations": {
                        "/nix/store/fixed.drv": {
                            "name": "fixed",
                            "env": {
                                "name": "fixed",
                                "out": "/nix/store/fixed-out",
                                "outputs": "out",
                                "pname": "fixed",
                                "version": "1.0",
                            },
                            "outputs": {
                                "out": {
                                    "hash": "sha256-test",
                                    "method": "flat",
                                },
                            },
                        },
                    },
                    "version": 4,
                }
            ),
            returncode=0,
            stderr="",
        )

    monkeypatch.setattr(sbomnix_derivation, "exec_cmd", fake_exec_cmd)

    loaded = sbomnix_derivation.load_many(
        ["/nix/store/fixed-out"],
        output_paths_by_drv={
            "/nix/store/fixed-out": {"/nix/store/fixed-out"},
        },
        batch_size=50,
    )

    assert list(loaded) == ["/nix/store/fixed.drv"]
    assert loaded["/nix/store/fixed.drv"].outputs == ["/nix/store/fixed-out"]


def test_load_many_can_ignore_missing_output_derivations(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        query_paths = cmd[3:-4]
        if "/nix/store/missing-out" in query_paths:
            assert kwargs == {"raise_on_error": False, "log_error": False}
            return None
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "derivations": {
                        "/nix/store/good.drv": {
                            "name": "good",
                            "env": {
                                "name": "good",
                                "pname": "good",
                                "version": "1.0",
                            },
                            "outputs": {
                                "out": {"path": "/nix/store/good-out"},
                            },
                        },
                    },
                    "version": 4,
                }
            ),
            returncode=0,
            stderr="",
        )

    monkeypatch.setattr(sbomnix_derivation, "exec_cmd", fake_exec_cmd)

    loaded = sbomnix_derivation.load_many(
        ["/nix/store/good-out", "/nix/store/missing-out"],
        output_paths_by_drv={
            "/nix/store/good-out": {"/nix/store/good-out"},
            "/nix/store/missing-out": {"/nix/store/missing-out"},
        },
        batch_size=50,
        ignore_missing=True,
    )

    assert list(loaded) == ["/nix/store/good.drv"]
    assert [call[0][3:-4] for call in calls] == [
        ["/nix/store/good-out", "/nix/store/missing-out"],
        ["/nix/store/good-out"],
        ["/nix/store/missing-out"],
    ]


def test_store_add_paths_loads_each_deriver_once(monkeypatch):
    load_calls = []

    class FakeDrv:
        """Minimal derivation double for store batching tests."""

        def __init__(self, store_path):
            self.store_path = store_path
            self.outputs = []

        def add_output_path(self, path):
            if path and path not in self.outputs:
                self.outputs.append(path)

        def set_cpe(self, _generator):
            return None

        def to_dict(self):
            return {"store_path": self.store_path, "outputs": self.outputs}

    def fake_find_derivers(_paths, batch_size=500):
        assert batch_size == 500
        return {
            "/nix/store/first-out": "/nix/store/shared.drv",
            "/nix/store/second-out": "/nix/store/shared.drv",
        }

    def fake_load_many(_paths, output_paths_by_drv=None, batch_size=200):
        assert output_paths_by_drv is not None
        load_calls.append(
            (
                list(_paths),
                {key: sorted(value) for key, value in output_paths_by_drv.items()},
                batch_size,
            )
        )
        return {
            "/nix/store/shared.drv": FakeDrv("/nix/store/shared.drv"),
        }

    monkeypatch.setattr(sbomnix_fallback_store, "find_derivers", fake_find_derivers)
    monkeypatch.setattr(sbomnix_fallback_store, "load_many", fake_load_many)
    monkeypatch.setattr("os.path.exists", lambda _path: True)

    store = sbomnix_fallback_store.FallbackStore(buildtime=True, include_cpe=False)
    store.add_paths(["/nix/store/first-out", "/nix/store/second-out"])

    assert load_calls == [
        (
            ["/nix/store/shared.drv"],
            {
                "/nix/store/shared.drv": [
                    "/nix/store/first-out",
                    "/nix/store/second-out",
                ]
            },
            200,
        )
    ]
    assert (
        store.derivations["/nix/store/first-out"].store_path == "/nix/store/shared.drv"
    )
    assert (
        store.derivations["/nix/store/second-out"].store_path == "/nix/store/shared.drv"
    )
