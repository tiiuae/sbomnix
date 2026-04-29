#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for provenance digest and subject handling."""

import json
import logging
from types import SimpleNamespace

from common.log import LOG
from common.nix_utils import parse_nix_derivation_show
from provenance import main as provenance_main
from provenance.dependencies import (
    DependencyHooks,
    dependency_package,
    get_dependencies,
)
from provenance.digests import normalize_digest, output_digest
from provenance.subjects import SubjectHooks, get_subjects, output_path


def _dependency_hooks(*, exec_cmd_fn, query_path_hashes_fn=None):
    return DependencyHooks(
        exec_cmd_fn=exec_cmd_fn,
        query_path_hashes_fn=query_path_hashes_fn,
        parse_nix_derivation_show_fn=parse_nix_derivation_show,
        normalize_digest_fn=normalize_digest,
        output_digest_fn=output_digest,
        output_path_fn=output_path,
        log=LOG,
    )


def _subject_hooks(exec_cmd_fn):
    return SubjectHooks(
        exec_cmd_fn=exec_cmd_fn,
        normalize_digest_fn=normalize_digest,
        output_digest_fn=output_digest,
        output_path_fn=output_path,
        log=LOG,
    )


def _path_info_paths(cmd):
    if cmd[:5] != ["nix", "path-info", "--json", "--json-format", "1"]:
        return None
    args = cmd[5:]
    if "--extra-experimental-features" in args:
        args = args[: args.index("--extra-experimental-features")]
    return args


def test_get_dependencies_supports_nix_2_33_wrapped_json():
    drv_path = "/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    dep_basename = "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-dependency.drv"
    dep_path = f"/nix/store/{dep_basename}"
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def fake_exec_cmd(cmd, **kwargs):
        if _path_info_paths(cmd) == [drv_path]:
            return SimpleNamespace(
                stdout=json.dumps({drv_path: {"references": [dep_path]}})
            )
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
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    assert get_dependencies(
        drv_path,
        hooks=_dependency_hooks(
            exec_cmd_fn=fake_exec_cmd,
            query_path_hashes_fn=lambda _paths, **_kwargs: [
                "sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
            ],
        ),
    ) == [
        {
            "name": "dependency",
            "uri": dep_path,
            "digest": {"sha256": digest},
            "annotations": {"version": "1.2.3"},
        }
    ]


def test_normalize_digest_does_not_shell_out():
    assert normalize_digest(
        "sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    ) == {"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}
    assert normalize_digest("sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=") == {
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    }
    assert normalize_digest(
        "77a94a83ccab42a68278ac5d3e340dcefecd736dd4feff1de71dec137b6b44ce",
        "r:sha256",
    ) == {"sha256": "77a94a83ccab42a68278ac5d3e340dcefecd736dd4feff1de71dec137b6b44ce"}


def test_normalize_digest_rejects_overflowing_nix32_values():
    assert normalize_digest("sha256:" + ("z" * 52)) is None


def test_dependency_package_logs_non_normalized_digest_fallback(caplog):
    drv_path = "/nix/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-dependency.drv"

    with caplog.at_level(logging.WARNING, logger=LOG.name):
        package = dependency_package(
            drv_path,
            "sha999:abc",
            {},
            {},
            hooks=DependencyHooks(
                normalize_digest_fn=normalize_digest,
                output_digest_fn=output_digest,
                log=LOG,
            ),
        )

    assert package == {
        "name": "dependency",
        "uri": drv_path,
        "digest": {"sha999": "abc"},
    }
    assert "Falling back to non-normalized digest" in caplog.text


def test_get_dependencies_prefers_fixed_output_digest_for_output_paths():
    drv_path = "/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    dep_drv_basename = "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source.drv"
    dep_out_basename = "2ccccccccccccccccccccccccccccccc-source"
    dep_out_path = f"/nix/store/{dep_out_basename}"
    metadata_digest = "77a94a83ccab42a68278ac5d3e340dcefecd736dd4feff1de71dec137b6b44ce"

    def fake_exec_cmd(cmd, **kwargs):
        if _path_info_paths(cmd) == [drv_path]:
            return SimpleNamespace(
                stdout=json.dumps({drv_path: {"references": [dep_out_path]}})
            )
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
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    assert get_dependencies(
        drv_path,
        hooks=_dependency_hooks(
            exec_cmd_fn=fake_exec_cmd,
            query_path_hashes_fn=lambda _paths, **_kwargs: [
                "sha256:09i0w2qz3i5yp7m3yziq4z2n2r2v9s6d3n8j4x1q8k0m5a6b7c8d"
            ],
        ),
    ) == [
        {
            "name": "source",
            "uri": dep_out_path,
            "digest": {"sha256": metadata_digest},
            "annotations": {"version": "1.2.3"},
        }
    ]


def test_get_dependencies_maps_env_only_output_paths_back_to_derivations():
    drv_path = "/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    dep_out_basename = "2ccccccccccccccccccccccccccccccc-source"
    dep_out_path = f"/nix/store/{dep_out_basename}"
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def fake_exec_cmd(cmd, **kwargs):
        if _path_info_paths(cmd) == [drv_path]:
            return SimpleNamespace(
                stdout=json.dumps({drv_path: {"references": [dep_out_path]}})
            )
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

    assert get_dependencies(
        drv_path,
        hooks=_dependency_hooks(
            exec_cmd_fn=fake_exec_cmd,
            query_path_hashes_fn=lambda _paths, **_kwargs: [
                "sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
            ],
        ),
    ) == [
        {
            "name": "special-source",
            "uri": dep_out_path,
            "digest": {"sha256": digest},
            "annotations": {"version": "1.2.3"},
        }
    ]


def test_get_subjects_falls_back_to_env_output_paths():
    output_path_value = "/custom/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nghttp2-1.68.1"
    output_hash = "1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def fake_exec_cmd(cmd, **kwargs):
        if _path_info_paths(cmd) == [output_path_value]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {output_path_value: {"narHash": f"sha256:{output_hash}"}}
                )
            )
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    assert get_subjects(
        {"out": {"method": "nar"}},
        env={"out": output_path_value},
        hooks=_subject_hooks(fake_exec_cmd),
    ) == [
        {
            "name": "out",
            "uri": output_path_value,
            "digest": {"sha256": digest},
        }
    ]


def test_get_subjects_prefers_derivation_hash_for_realized_flat_outputs():
    output_path_value = "/custom/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nghttp2-1.68.1"
    output_hash = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def fail_exec_cmd(cmd, **kwargs):
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    assert get_subjects(
        {"out": {"method": "flat", "hash": output_hash}},
        env={"out": output_path_value},
        hooks=_subject_hooks(fail_exec_cmd),
    ) == [
        {
            "name": "out",
            "uri": output_path_value,
            "digest": {"sha256": digest},
        }
    ]


def test_get_subjects_uses_derivation_hash_when_output_is_not_realized():
    output_path_value = "/custom/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nghttp2-1.68.1"
    output_hash = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def fail_exec_cmd(cmd, **kwargs):
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    assert get_subjects(
        {"out": {"method": "nar", "hash": output_hash}},
        env={"out": output_path_value},
        hooks=_subject_hooks(fail_exec_cmd),
    ) == [
        {
            "name": "out",
            "uri": output_path_value,
            "digest": {"sha256": digest},
        }
    ]


def test_get_subjects_supports_legacy_r_sha256_metadata():
    output_path_value = "/custom/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nghttp2-1.68.1"
    digest = "77a94a83ccab42a68278ac5d3e340dcefecd736dd4feff1de71dec137b6b44ce"

    def fail_exec_cmd(cmd, **kwargs):
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    assert get_subjects(
        {
            "out": {
                "hash": digest,
                "hashAlgo": "r:sha256",
            }
        },
        env={"out": output_path_value},
        hooks=_subject_hooks(fail_exec_cmd),
    ) == [
        {
            "name": "out",
            "uri": output_path_value,
            "digest": {"sha256": digest},
        }
    ]


def test_get_subjects_skips_unrealized_outputs_without_digest():
    output_path_value = "/custom/store/2ccccccccccccccccccccccccccccccc-nghttp2-doc"

    def fake_exec_cmd(cmd, **_kwargs):
        assert _path_info_paths(cmd) == [output_path_value]

    assert not get_subjects(
        {"out": {"method": "nar"}},
        env={"out": output_path_value},
        hooks=_subject_hooks(fake_exec_cmd),
    )


def test_get_subjects_skip_only_missing_unrealized_outputs():
    output_path_value = "/custom/store/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nghttp2-1.68.1"
    missing_path = "/custom/store/2ccccccccccccccccccccccccccccccc-nghttp2-doc"
    output_hash = "1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def fake_exec_cmd(cmd, **kwargs):
        if _path_info_paths(cmd) == [output_path_value]:
            return SimpleNamespace(
                stdout=json.dumps(
                    {output_path_value: {"narHash": f"sha256:{output_hash}"}}
                )
            )
        if _path_info_paths(cmd) == [missing_path]:
            return None
        raise AssertionError(f"unexpected command: {cmd} kwargs={kwargs}")

    assert get_subjects(
        {"out": {"path": output_path_value}, "doc": {"path": missing_path}},
        hooks=_subject_hooks(fake_exec_cmd),
    ) == [
        {
            "name": "out",
            "uri": output_path_value,
            "digest": {"sha256": digest},
        }
    ]


def test_provenance_uses_store_path_hint_for_nix_2_33_outputs_without_path(monkeypatch):
    target = "/custom/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    drv_basename = "0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"
    out_basename = "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-root"
    output_hash = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

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
