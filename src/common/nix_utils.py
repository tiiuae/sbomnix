# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for normalizing nix store paths and derivation JSON."""

import json
import os
import re

RE_NIX_STORE_PATH_BASENAME = re.compile(r"^[0-9a-z]{32}-.+")
RE_NIX_STORE_PATH = re.compile(r"(?P<store_path>/(?:[^/\s:]+/)+[0-9a-z]{32}-[^/\s:]+)")


def get_nix_store_dir(path=None, default="/nix/store"):
    """Infer the nix store directory from an absolute store path-like string."""
    if path:
        match = RE_NIX_STORE_PATH.search(str(path))
        if match:
            return os.path.dirname(match.group("store_path"))
    return default


def normalize_nix_store_path(path, store_dir="/nix/store"):
    """Return an absolute store path for basename-only store path strings."""
    if not isinstance(path, str) or not path:
        return path
    if os.path.isabs(path) or not RE_NIX_STORE_PATH_BASENAME.match(path):
        return path
    return os.path.join(store_dir, path)


def _iter_nix_store_dir_candidates(value):
    """Yield strings that may reveal the nix store directory."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_nix_store_dir_candidates(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_nix_store_dir_candidates(item)


def _infer_nix_store_dir(drv_info, default="/nix/store"):
    """Infer the nix store directory from derivation fields when keys are relative."""
    if not isinstance(drv_info, dict):
        return default
    for candidate in _iter_nix_store_dir_candidates(
        {
            "builder": drv_info.get("builder"),
            "outputs": drv_info.get("outputs"),
            "env": drv_info.get("env"),
        }
    ):
        store_dir = get_nix_store_dir(candidate, default=None)
        if store_dir:
            return store_dir
    return default


def _normalize_nix_derivation_info(drv_info, store_dir):
    """Normalize basename-only store paths within derivation info."""
    if not isinstance(drv_info, dict):
        return drv_info

    normalized = dict(drv_info)

    outputs = normalized.get("outputs")
    if isinstance(outputs, dict):
        normalized["outputs"] = {}
        for name, output in outputs.items():
            if isinstance(output, dict):
                output = dict(output)
                if output.get("path"):
                    output["path"] = normalize_nix_store_path(output["path"], store_dir)
            normalized["outputs"][name] = output

    env = normalized.get("env")
    if isinstance(env, dict):
        normalized["env"] = {
            key: normalize_nix_store_path(value, store_dir)
            for key, value in env.items()
        }

    inputs = normalized.get("inputs")
    if isinstance(inputs, dict):
        normalized_inputs = dict(inputs)
        srcs = normalized_inputs.get("srcs")
        if isinstance(srcs, list):
            normalized_inputs["srcs"] = [
                normalize_nix_store_path(src, store_dir) for src in srcs
            ]
        drvs = normalized_inputs.get("drvs")
        if isinstance(drvs, dict):
            normalized_inputs["drvs"] = {
                normalize_nix_store_path(path, store_dir): outputs
                for path, outputs in drvs.items()
            }
        normalized["inputs"] = normalized_inputs

    input_srcs = normalized.get("inputSrcs")
    if isinstance(input_srcs, list):
        normalized["inputSrcs"] = [
            normalize_nix_store_path(src, store_dir) for src in input_srcs
        ]

    input_drvs = normalized.get("inputDrvs")
    if isinstance(input_drvs, dict):
        normalized["inputDrvs"] = {
            normalize_nix_store_path(path, store_dir): outputs
            for path, outputs in input_drvs.items()
        }

    return normalized


def parse_nix_derivation_show(stdout, store_path_hint=None):
    """Normalize `nix derivation show` JSON across legacy and wrapped formats."""
    payload = json.loads(stdout)
    derivations = (
        payload.get("derivations", payload) if isinstance(payload, dict) else {}
    )
    if not isinstance(derivations, dict):
        return {}

    normalized = {}
    fallback_store_dir = get_nix_store_dir(store_path_hint)
    for drv_path, drv_info in derivations.items():
        store_dir = get_nix_store_dir(drv_path, default=None)
        if not store_dir:
            store_dir = _infer_nix_store_dir(drv_info, default=fallback_store_dir)
        normalized_drv_path = normalize_nix_store_path(drv_path, store_dir)
        normalized[normalized_drv_path] = _normalize_nix_derivation_info(
            drv_info, store_dir
        )
    return normalized
