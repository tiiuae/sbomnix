#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

"""Unit tests for whitespace-safe subprocess argv construction."""

import json
import logging
from types import SimpleNamespace

import pytest

from common import flakeref as common_flakeref
from common.errors import FlakeRefRealisationError, FlakeRefResolutionError
from common.nix_utils import get_nix_store_dir, parse_nix_derivation_show
from common.proc import exec_cmd
from nixmeta import scanner
from nixupdate import nix_outdated
from provenance import main as provenance_main
from sbomnix import nix as sbomnix_nix
from sbomnix.meta import Meta
from vulnxscan.vulnscan import VulnScan


def test_try_resolve_flakeref_uses_argv_lists(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        if cmd[1] == "eval":
            return SimpleNamespace(stdout="/nix/store/resolved\n", returncode=0)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(common_flakeref, "exec_cmd", fake_exec_cmd)

    resolved = common_flakeref.try_resolve_flakeref(
        "/tmp/my flake#pkg", force_realise=True, impure=True
    )

    assert resolved == "/nix/store/resolved"
    assert calls == [
        (
            [
                "nix",
                "eval",
                "--raw",
                "/tmp/my flake#pkg",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
                "--impure",
            ],
            {"raise_on_error": False, "return_error": True, "log_error": False},
        ),
        (
            [
                "nix",
                "build",
                "--no-link",
                "/tmp/my flake#pkg",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
                "--impure",
            ],
            {"raise_on_error": False, "return_error": True, "log_error": False},
        ),
    ]


def test_try_resolve_flakeref_raises_on_failed_force_realise(monkeypatch):
    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[1] == "eval":
            return SimpleNamespace(stdout="/nix/store/resolved\n", returncode=0)
        return SimpleNamespace(stdout="", stderr="build failed", returncode=1)

    monkeypatch.setattr(common_flakeref, "exec_cmd", fake_exec_cmd)

    with pytest.raises(FlakeRefRealisationError, match="build failed"):
        common_flakeref.try_resolve_flakeref("/tmp/my flake#pkg", force_realise=True)


def test_try_resolve_flakeref_raises_on_failed_eval_for_flakeref(monkeypatch):
    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout="", stderr="attribute missing", returncode=1)

    monkeypatch.setattr(common_flakeref, "exec_cmd", fake_exec_cmd)

    with pytest.raises(FlakeRefResolutionError, match="attribute missing"):
        common_flakeref.try_resolve_flakeref(".#missing")


def test_try_resolve_flakeref_returns_none_for_non_flake_path(monkeypatch):
    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(
            stdout="",
            stderr="does not contain a 'flake.nix'",
            returncode=1,
        )

    monkeypatch.setattr(common_flakeref, "exec_cmd", fake_exec_cmd)

    resolved = common_flakeref.try_resolve_flakeref("/nix/store/not-a-flake-output")

    assert resolved is None


@pytest.mark.parametrize("path", ["missing", "./missing", "foo/bar"])
def test_try_resolve_flakeref_returns_none_for_missing_relative_paths(
    monkeypatch, path
):
    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout="", stderr="dummy eval failure", returncode=1)

    monkeypatch.setattr(common_flakeref, "exec_cmd", fake_exec_cmd)

    resolved = common_flakeref.try_resolve_flakeref(path)

    assert resolved is None


@pytest.mark.parametrize("name", ["artifact#1", "artifact?1"])
def test_try_resolve_flakeref_returns_none_for_existing_non_flake_path_with_fragment_chars(
    tmp_path, monkeypatch, name
):
    artifact = tmp_path / name
    artifact.write_text("not a flake", encoding="utf-8")

    def fake_exec_cmd(_cmd, **_kwargs):
        return SimpleNamespace(stdout="", stderr="attribute missing", returncode=1)

    monkeypatch.setattr(common_flakeref, "exec_cmd", fake_exec_cmd)

    resolved = common_flakeref.try_resolve_flakeref(artifact.as_posix())

    assert resolved is None


def test_flakeref_realisation_error_accepts_none_stderr():
    error = FlakeRefRealisationError("/tmp/my flake#pkg", None)

    assert error.stderr == ""
    assert str(error) == "Failed force-realising flakeref '/tmp/my flake#pkg'"


def test_flake_ref_resolution_error_preserves_stderr_verbatim():
    error = FlakeRefResolutionError(".#missing", "attribute missing\n")

    assert error.stderr == "attribute missing\n"
    assert str(error) == "Failed evaluating flakeref '.#missing': attribute missing"


def test_exec_cmd_rejects_string_commands():
    with pytest.raises(TypeError, match="argv sequence"):
        exec_cmd("nix build .#sbomnix")


def test_find_deriver_uses_argv_list(monkeypatch):
    calls = []
    drv_path = "/nix/store/my drv.drv"

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout=json.dumps({drv_path: {}}))

    monkeypatch.setattr(sbomnix_nix, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(sbomnix_nix.os.path, "exists", lambda path: path == drv_path)

    resolved = sbomnix_nix.find_deriver("/nix/store/my output")

    assert resolved == drv_path
    assert calls == [
        (
            [
                "nix",
                "derivation",
                "show",
                "/nix/store/my output",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
            ],
            {"raise_on_error": False, "log_error": False},
        )
    ]


def test_find_deriver_supports_nix_2_33_wrapped_json(monkeypatch):
    path = "/nix/store/my output"
    drv_basename = "4rpn9q86mj9sxrfavhz1qgx7a8sdbndw-nghttp2-1.68.1.drv"
    drv_path = f"/nix/store/{drv_basename}"
    stale_qpi_deriver = "/nix/store/stale-nghttp2-1.68.1.drv"

    def fake_exec_cmd(cmd, **kwargs):
        if cmd[:3] == ["nix", "derivation", "show"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "derivations": {drv_basename: {}},
                        "version": 4,
                    }
                )
            )
        if cmd == ["nix-store", "-qd", path]:
            return SimpleNamespace(stdout=f"{stale_qpi_deriver}\n")
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(sbomnix_nix, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        sbomnix_nix.os.path,
        "exists",
        lambda candidate: candidate == drv_path,
    )

    assert sbomnix_nix.find_deriver(path) == drv_path


def test_parse_nix_derivation_show_normalizes_nix_2_33_store_paths():
    drv_basename = "4rpn9q86mj9sxrfavhz1qgx7a8sdbndw-nghttp2-1.68.1.drv"
    out_basename = "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nghttp2-1.68.1"
    src_basename = "2ccccccccccccccccccccccccccccccc-source"
    dep_basename = "3ddddddddddddddddddddddddddddddd-zlib-1.3.1.drv"

    parsed = parse_nix_derivation_show(
        json.dumps(
            {
                "version": 4,
                "derivations": {
                    drv_basename: {
                        "name": "nghttp2",
                        "builder": "/custom/store/4eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-bash/bin/bash",
                        "outputs": {"out": {"path": out_basename}},
                        "inputs": {
                            "srcs": [src_basename],
                            "drvs": {dep_basename: ["out"]},
                        },
                        "env": {"out": out_basename, "name": "nghttp2-1.68.1"},
                    }
                },
            }
        )
    )

    drv_path = f"/custom/store/{drv_basename}"
    assert list(parsed) == [drv_path]
    assert parsed[drv_path]["outputs"]["out"]["path"] == f"/custom/store/{out_basename}"
    assert parsed[drv_path]["inputs"]["srcs"] == [f"/custom/store/{src_basename}"]
    assert list(parsed[drv_path]["inputs"]["drvs"]) == [f"/custom/store/{dep_basename}"]
    assert parsed[drv_path]["env"]["out"] == f"/custom/store/{out_basename}"


def test_get_nix_store_dir_ignores_colon_separated_env_paths():
    value = (
        "--prefix PATH : "
        "/custom/store/4eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-git/bin:"
        "/custom/store/5fffffffffffffffffffffffffffffff-graphviz/bin"
    )

    assert get_nix_store_dir(value, default=None) == "/custom/store"


def test_parse_nix_derivation_show_infers_store_dir_from_path_like_env_values():
    drv_basename = "4rpn9q86mj9sxrfavhz1qgx7a8sdbndw-nghttp2-1.68.1.drv"
    out_basename = "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nghttp2-1.68.1"

    parsed = parse_nix_derivation_show(
        json.dumps(
            {
                "version": 4,
                "derivations": {
                    drv_basename: {
                        "name": "nghttp2",
                        "outputs": {"out": {"method": "nar"}},
                        "env": {
                            "out": out_basename,
                            "makeWrapperArgs": (
                                "--prefix PATH : "
                                "/custom/store/4eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-git/bin:"
                                "/custom/store/5fffffffffffffffffffffffffffffff-graphviz/bin"
                            ),
                        },
                    }
                },
            }
        )
    )

    drv_path = f"/custom/store/{drv_basename}"
    assert list(parsed) == [drv_path]
    assert parsed[drv_path]["env"]["out"] == f"/custom/store/{out_basename}"


def test_get_dependencies_supports_nix_2_33_wrapped_json(monkeypatch):
    drv_path = "/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    dep_basename = "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-dependency.drv"
    dep_path = f"/nix/store/{dep_basename}"
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    real_exec_cmd = provenance_main.exec_cmd

    def fake_exec_cmd(cmd, **kwargs):
        if cmd == [
            "nix-store",
            "--query",
            "--references",
            "--include-outputs",
            drv_path,
        ]:
            return SimpleNamespace(stdout=f"{dep_path}\n")
        if cmd[:4] == ["nix", "derivation", "show", "-r"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "derivations": {
                            dep_basename: {
                                "name": "dependency",
                                "env": {"version": "1.2.3"},
                            }
                        },
                        "version": 4,
                    }
                )
            )
        if cmd[:3] == ["nix", "hash", "convert"]:
            return real_exec_cmd(cmd, **kwargs)
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        provenance_main,
        "query_store_hashes",
        lambda paths: ["sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"],
    )

    assert provenance_main.get_dependencies(drv_path) == [
        {
            "name": "dependency",
            "uri": dep_path,
            "digest": {"sha256": digest},
            "annotations": {"version": "1.2.3"},
        }
    ]


def test_normalize_digest_does_not_shell_out(monkeypatch):
    def fail_exec_cmd(cmd, **kwargs):
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fail_exec_cmd)

    assert provenance_main._normalize_digest(
        "sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    ) == {"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}
    assert provenance_main._normalize_digest(
        "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    ) == {"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}
    assert provenance_main._normalize_digest(
        "77a94a83ccab42a68278ac5d3e340dcefecd736dd4feff1de71dec137b6b44ce",
        "r:sha256",
    ) == {"sha256": "77a94a83ccab42a68278ac5d3e340dcefecd736dd4feff1de71dec137b6b44ce"}


def test_normalize_digest_rejects_overflowing_nix32_values(monkeypatch):
    def fail_exec_cmd(cmd, **kwargs):
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fail_exec_cmd)

    assert provenance_main._normalize_digest("sha256:" + ("z" * 52)) is None


def test_dependency_package_logs_non_normalized_digest_fallback(caplog):
    drv_path = "/nix/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-dependency.drv"

    with caplog.at_level(logging.WARNING, logger=provenance_main.LOG.name):
        package = provenance_main._dependency_package(drv_path, "sha999:abc", {}, {})

    assert package == {
        "name": "dependency",
        "uri": drv_path,
        "digest": {"sha999": "abc"},
    }
    assert "Falling back to non-normalized digest" in caplog.text


def test_get_dependencies_prefers_fixed_output_digest_for_output_paths(monkeypatch):
    drv_path = "/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    dep_drv_basename = "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source.drv"
    dep_out_basename = "2ccccccccccccccccccccccccccccccc-source"
    dep_out_path = f"/nix/store/{dep_out_basename}"
    metadata_digest = "77a94a83ccab42a68278ac5d3e340dcefecd736dd4feff1de71dec137b6b44ce"
    real_exec_cmd = provenance_main.exec_cmd

    def fake_exec_cmd(cmd, **kwargs):
        if cmd == [
            "nix-store",
            "--query",
            "--references",
            "--include-outputs",
            drv_path,
        ]:
            return SimpleNamespace(stdout=f"{dep_out_path}\n")
        if cmd[:4] == ["nix", "derivation", "show", "-r"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "derivations": {
                            dep_drv_basename: {
                                "name": "source",
                                "outputs": {
                                    "out": {
                                        "path": dep_out_basename,
                                        "hash": metadata_digest,
                                        "hashAlgo": "r:sha256",
                                    }
                                },
                                "env": {"version": "1.2.3"},
                            }
                        },
                        "version": 4,
                    }
                )
            )
        if cmd[:3] == ["nix", "hash", "convert"]:
            return real_exec_cmd(cmd, **kwargs)
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        provenance_main,
        "query_store_hashes",
        lambda paths: ["sha256:09i0w2qz3i5yp7m3yziq4z2n2r2v9s6d3n8j4x1q8k0m5a6b7c8d"],
    )

    assert provenance_main.get_dependencies(drv_path) == [
        {
            "name": "source",
            "uri": dep_out_path,
            "digest": {"sha256": metadata_digest},
            "annotations": {"version": "1.2.3"},
        }
    ]


def test_get_dependencies_maps_env_only_output_paths_back_to_derivations(monkeypatch):
    drv_path = "/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    dep_out_basename = "2ccccccccccccccccccccccccccccccc-source"
    dep_out_path = f"/nix/store/{dep_out_basename}"
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def fake_exec_cmd(cmd, **kwargs):
        if cmd == [
            "nix-store",
            "--query",
            "--references",
            "--include-outputs",
            drv_path,
        ]:
            return SimpleNamespace(stdout=f"{dep_out_path}\n")
        if cmd[:4] == ["nix", "derivation", "show", "-r"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "derivations": {
                            "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source.drv": {
                                "name": "special-source",
                                "outputs": {"out": {"method": "nar"}},
                                "env": {
                                    "out": dep_out_basename,
                                    "version": "1.2.3",
                                },
                            }
                        },
                        "version": 4,
                    }
                )
            )
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        provenance_main,
        "query_store_hashes",
        lambda paths: ["sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"],
    )

    assert provenance_main.get_dependencies(drv_path) == [
        {
            "name": "special-source",
            "uri": dep_out_path,
            "digest": {"sha256": digest},
            "annotations": {"version": "1.2.3"},
        }
    ]


def test_get_subjects_falls_back_to_env_output_paths(monkeypatch):
    output_path = "/custom/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nghttp2-1.68.1"
    output_hash = "1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    real_exec_cmd = provenance_main.exec_cmd

    def fake_exec_cmd(cmd, **kwargs):
        if cmd == ["nix-store", "--query", "--hash", output_path]:
            return SimpleNamespace(stdout=f"sha256:{output_hash}\n")
        if cmd[:3] == ["nix", "hash", "convert"]:
            return real_exec_cmd(cmd, **kwargs)
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fake_exec_cmd)

    assert provenance_main.get_subjects(
        {"out": {"method": "nar"}},
        env={"out": output_path},
    ) == [
        {
            "name": "out",
            "uri": output_path,
            "digest": {"sha256": digest},
        }
    ]


def test_get_subjects_prefers_derivation_hash_for_realized_flat_outputs(monkeypatch):
    output_path = "/custom/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nghttp2-1.68.1"
    output_hash = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    real_exec_cmd = provenance_main.exec_cmd

    def fake_exec_cmd(cmd, **kwargs):
        if cmd[:3] == ["nix", "hash", "convert"]:
            return real_exec_cmd(cmd, **kwargs)
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fake_exec_cmd)

    assert provenance_main.get_subjects(
        {"out": {"method": "flat", "hash": output_hash}},
        env={"out": output_path},
    ) == [
        {
            "name": "out",
            "uri": output_path,
            "digest": {"sha256": digest},
        }
    ]


def test_get_subjects_uses_derivation_hash_when_output_is_not_realized(monkeypatch):
    output_path = "/custom/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nghttp2-1.68.1"
    output_hash = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    real_exec_cmd = provenance_main.exec_cmd

    def fake_exec_cmd(cmd, **kwargs):
        if cmd == ["nix-store", "--query", "--hash", output_path]:
            return None
        if cmd[:3] == ["nix", "hash", "convert"]:
            return real_exec_cmd(cmd, **kwargs)
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fake_exec_cmd)

    assert provenance_main.get_subjects(
        {"out": {"method": "nar", "hash": output_hash}},
        env={"out": output_path},
    ) == [
        {
            "name": "out",
            "uri": output_path,
            "digest": {"sha256": digest},
        }
    ]


def test_get_subjects_supports_legacy_r_sha256_metadata(monkeypatch):
    output_path = "/custom/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nghttp2-1.68.1"
    digest = "77a94a83ccab42a68278ac5d3e340dcefecd736dd4feff1de71dec137b6b44ce"
    real_exec_cmd = provenance_main.exec_cmd

    def fake_exec_cmd(cmd, **kwargs):
        if cmd[:3] == ["nix", "hash", "convert"]:
            return real_exec_cmd(cmd, **kwargs)
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fake_exec_cmd)

    assert provenance_main.get_subjects(
        {
            "out": {
                "hash": digest,
                "hashAlgo": "r:sha256",
            }
        },
        env={"out": output_path},
    ) == [
        {
            "name": "out",
            "uri": output_path,
            "digest": {"sha256": digest},
        }
    ]


def test_get_subjects_skips_unrealized_outputs_without_digest(monkeypatch):
    output_path = "/custom/store/2ccccccccccccccccccccccccccccccc-nghttp2-doc"

    def fake_exec_cmd(cmd, **_kwargs):
        assert cmd == ["nix-store", "--query", "--hash", output_path]

    monkeypatch.setattr(provenance_main, "exec_cmd", fake_exec_cmd)

    assert not provenance_main.get_subjects(
        {"out": {"method": "nar"}},
        env={"out": output_path},
    )


def test_get_subjects_skip_only_missing_unrealized_outputs(monkeypatch):
    output_path = "/custom/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nghttp2-1.68.1"
    missing_path = "/custom/store/2ccccccccccccccccccccccccccccccc-nghttp2-doc"
    output_hash = "1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    real_exec_cmd = provenance_main.exec_cmd

    def fake_exec_cmd(cmd, **kwargs):
        if cmd == ["nix-store", "--query", "--hash", output_path]:
            return SimpleNamespace(stdout=f"sha256:{output_hash}\n")
        if cmd == ["nix-store", "--query", "--hash", missing_path]:
            return None
        if cmd[:3] == ["nix", "hash", "convert"]:
            return real_exec_cmd(cmd, **kwargs)
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fake_exec_cmd)

    assert provenance_main.get_subjects(
        {"out": {"path": output_path}, "doc": {"path": missing_path}},
    ) == [
        {
            "name": "out",
            "uri": output_path,
            "digest": {"sha256": digest},
        }
    ]


def test_provenance_uses_store_path_hint_for_nix_2_33_outputs_without_path(monkeypatch):
    target = "/custom/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    drv_basename = "0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    out_basename = "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-root"
    output_hash = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    real_exec_cmd = provenance_main.exec_cmd

    def fake_exec_cmd(cmd, **kwargs):
        if cmd[:3] == ["nix", "derivation", "show"]:
            assert cmd[3] == target
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "version": 4,
                        "derivations": {
                            drv_basename: {
                                "name": "root",
                                "outputs": {
                                    "out": {
                                        "method": "nar",
                                        "hash": output_hash,
                                    }
                                },
                                "env": {"out": out_basename},
                            }
                        },
                    }
                )
            )
        if cmd[:3] == ["nix", "hash", "convert"]:
            return real_exec_cmd(cmd, **kwargs)
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        provenance_main, "get_dependencies", lambda *_args, **_kwargs: []
    )

    metadata = provenance_main.BuildMeta("", "", "", "", "", "{}", "{}")
    provenance = provenance_main.provenance(target, metadata)

    assert provenance["subject"] == [
        {
            "name": "out",
            "uri": f"/custom/store/{out_basename}",
            "digest": {"sha256": digest},
        }
    ]


def test_provenance_keeps_fixed_output_subjects_when_output_is_not_realized(
    monkeypatch,
):
    target = "/custom/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    drv_basename = "0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    out_basename = "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-root"
    output_hash = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    real_exec_cmd = provenance_main.exec_cmd

    def fake_exec_cmd(cmd, **kwargs):
        if cmd[:3] == ["nix", "derivation", "show"]:
            assert cmd[3] == target
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "version": 4,
                        "derivations": {
                            drv_basename: {
                                "name": "root",
                                "outputs": {
                                    "out": {"method": "nar", "hash": output_hash}
                                },
                                "env": {"out": out_basename},
                            }
                        },
                    }
                )
            )
        if cmd == ["nix-store", "--query", "--hash", f"/custom/store/{out_basename}"]:
            return None
        if cmd[:3] == ["nix", "hash", "convert"]:
            return real_exec_cmd(cmd, **kwargs)
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        provenance_main, "get_dependencies", lambda *_args, **_kwargs: []
    )

    metadata = provenance_main.BuildMeta("", "", "", "", "", "{}", "{}")
    provenance = provenance_main.provenance(target, metadata)

    assert provenance["subject"] == [
        {
            "name": "out",
            "uri": f"/custom/store/{out_basename}",
            "digest": {"sha256": digest},
        }
    ]


def test_get_flake_metadata_uses_argv_list(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout='{"path": "/nix/store/nixpkgs"}', returncode=0)

    monkeypatch.setattr(scanner, "exec_cmd", fake_exec_cmd)

    meta = scanner._get_flake_metadata("/tmp/my flake")

    assert meta == {"path": "/nix/store/nixpkgs"}
    assert calls == [
        (
            [
                "nix",
                "flake",
                "metadata",
                "/tmp/my flake",
                "--json",
                "--extra-experimental-features",
                "flakes",
                "--extra-experimental-features",
                "nix-command",
            ],
            {"raise_on_error": False, "return_error": True, "log_error": False},
        )
    ]


def test_run_nix_visualize_uses_argv_list(tmp_path, monkeypatch):
    calls = []
    output_path = tmp_path / "graph output.csv"

    class FakeTempFile:
        def __init__(self, path):
            self.name = path.as_posix()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(
        nix_outdated,
        "NamedTemporaryFile",
        lambda **_kwargs: FakeTempFile(output_path),
    )
    monkeypatch.setattr(nix_outdated, "exec_cmd", fake_exec_cmd)

    returned_path = nix_outdated._run_nix_visualize("/nix/store/my target")

    assert returned_path == output_path
    assert calls == [
        (
            [
                "nix-visualize",
                f"--output={output_path.as_posix()}",
                "/nix/store/my target",
            ],
            {},
        )
    ]


def test_get_flake_metadata_strips_nixpkgs_prefix_without_splitting_spaces(monkeypatch):
    calls = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout='{"path": "/nix/store/nixpkgs"}', returncode=0)

    monkeypatch.setattr(scanner, "exec_cmd", fake_exec_cmd)

    scanner._get_flake_metadata("nixpkgs=/tmp/my flake")

    assert calls[0][0][3] == "/tmp/my flake"


def test_meta_reads_nix_path_entry_with_spaces(monkeypatch):
    scanned = []

    monkeypatch.setenv("NIX_PATH", "foo=/tmp/other:nixpkgs=/tmp/my flake")
    monkeypatch.setattr(Meta, "_scan", lambda self, path: scanned.append(path) or path)

    resolved = Meta().get_nixpkgs_meta()

    assert resolved == "/tmp/my flake"
    assert scanned == ["/tmp/my flake"]


@pytest.mark.parametrize(
    ("buildtime", "expected_cmd"),
    [
        (False, ["vulnix", "/nix/store/my target", "-C", "--json"]),
        (True, ["vulnix", "/nix/store/my target", "--json"]),
    ],
)
def test_scan_vulnix_uses_argv_lists(monkeypatch, buildtime, expected_cmd):
    calls = []
    parsed = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout="[]", stderr="", returncode=0)

    monkeypatch.setattr("vulnxscan.vulnscan.exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        VulnScan, "_parse_vulnix", lambda self, stdout: parsed.append(stdout)
    )

    scanner_obj = VulnScan()
    scanner_obj.scan_vulnix("/nix/store/my target", buildtime=buildtime)

    assert parsed == ["[]"]
    assert calls == [
        (
            expected_cmd,
            {"raise_on_error": False, "return_error": True, "log_error": False},
        )
    ]
