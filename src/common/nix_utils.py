# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for normalizing nix store paths and derivation JSON."""

import json
import os
import re

from common.errors import InvalidNixJsonError

RE_NIX_STORE_PATH_BASENAME = re.compile(r"^[0-9a-z]{32}-.+")
RE_NIX_STORE_PATH = re.compile(r"(?P<store_path>/(?:[^/\s:]+/)+[0-9a-z]{32}-[^/\s:]+)")
NIX_DERIVATION_SHOW_JSON = "nix derivation show"
NIX_PATH_INFO_JSON = "nix path-info --json --json-format 1"


def get_nix_store_dir(path=None, default: str | None = "/nix/store") -> str | None:
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
            normalized_output = output
            if isinstance(output, dict):
                normalized_output = dict(output)
                if normalized_output.get("path"):
                    normalized_output["path"] = normalize_nix_store_path(
                        normalized_output["path"], store_dir
                    )
            normalized["outputs"][name] = normalized_output

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

    return normalized


def load_nix_json(stdout, command):
    """Load JSON produced by a Nix command and raise a user-facing error on drift."""
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as error:
        raise InvalidNixJsonError(command, f"invalid JSON: {error.msg}") from error


def parse_nix_derivation_show(stdout, store_path_hint=None):
    """Normalize `nix derivation show` JSON across direct and wrapped formats."""
    payload = load_nix_json(stdout, NIX_DERIVATION_SHOW_JSON)
    if not isinstance(payload, dict):
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            f"expected top-level object, got {type(payload).__name__}",
        )
    derivations = payload.get("derivations", payload)
    if not isinstance(derivations, dict):
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            f"expected `derivations` object, got {type(derivations).__name__}",
        )

    normalized = {}
    default_store_dir = get_nix_store_dir(store_path_hint) or "/nix/store"
    for drv_path, drv_info in derivations.items():
        _validate_derivation_entry(drv_path, drv_info)
        store_dir = get_nix_store_dir(drv_path, default=None)
        if not store_dir:
            store_dir = _infer_nix_store_dir(drv_info, default=default_store_dir)
        normalized_drv_path = normalize_nix_store_path(drv_path, store_dir)
        normalized[normalized_drv_path] = _normalize_nix_derivation_info(
            drv_info, store_dir
        )
    return normalized


def _validate_derivation_entry(drv_path, drv_info):
    """Validate the `nix derivation show` fields consumed by this project."""
    if not isinstance(drv_path, str) or not drv_path:
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            "expected derivation keys to be non-empty strings",
        )
    if not isinstance(drv_info, dict):
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            f"expected derivation `{drv_path}` to be an object",
        )
    _validate_optional_mapping(drv_info, "env", f"derivation `{drv_path}`")
    _validate_derivation_outputs(drv_path, drv_info)
    _check_optional_derivation_inputs(drv_path, drv_info)


def _validate_optional_mapping(record, field, owner):
    value = record.get(field)
    if value is not None and not isinstance(value, dict):
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            f"expected `{field}` in {owner} to be an object",
        )


def _validate_derivation_outputs(drv_path, drv_info):
    outputs = drv_info.get("outputs")
    if outputs is None:
        return
    if not isinstance(outputs, dict):
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            f"expected `outputs` in derivation `{drv_path}` to be an object",
        )
    for output_name, output in outputs.items():
        if not isinstance(output_name, str) or not output_name:
            raise InvalidNixJsonError(
                NIX_DERIVATION_SHOW_JSON,
                f"expected output names in derivation `{drv_path}` to be strings",
            )
        if not isinstance(output, dict):
            raise InvalidNixJsonError(
                NIX_DERIVATION_SHOW_JSON,
                f"expected output `{output_name}` in derivation `{drv_path}` "
                "to be an object",
            )
        output_path = output.get("path")
        if output_path is not None and not isinstance(output_path, str):
            raise InvalidNixJsonError(
                NIX_DERIVATION_SHOW_JSON,
                f"expected output `{output_name}` path in derivation `{drv_path}` "
                "to be a string",
            )


def _check_optional_derivation_inputs(drv_path, drv_info):
    """Validate input shape without requiring callers to consume dependencies."""
    inputs = drv_info.get("inputs")
    if inputs is not None:
        if not isinstance(inputs, dict):
            raise InvalidNixJsonError(
                NIX_DERIVATION_SHOW_JSON,
                f"expected `inputs` in derivation `{drv_path}` to be an object",
            )
        _validate_optional_mapping(inputs, "drvs", f"`inputs` for `{drv_path}`")
        srcs = inputs.get("srcs")
        if srcs is not None:
            if not isinstance(srcs, list):
                raise InvalidNixJsonError(
                    NIX_DERIVATION_SHOW_JSON,
                    f"expected `inputs.srcs` in derivation `{drv_path}` to be a list",
                )
            _validated_path_values(
                srcs,
                f"`inputs.srcs` in derivation `{drv_path}`",
                NIX_DERIVATION_SHOW_JSON,
            )
    _reject_legacy_derivation_inputs(drv_path, drv_info)


def _reject_legacy_derivation_inputs(drv_path, drv_info):
    for field in ("inputDrvs", "inputSrcs"):
        if field in drv_info:
            raise InvalidNixJsonError(
                NIX_DERIVATION_SHOW_JSON,
                f"unsupported legacy `{field}` in derivation `{drv_path}`",
            )


def nix_derivation_input_drv_paths(drv_path, drv_info):
    """Return validated input derivation paths from normalized derivation JSON."""
    inputs = _require_derivation_inputs(drv_path, drv_info)
    if "drvs" not in inputs:
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            f"missing `inputs.drvs` in derivation `{drv_path}`",
        )
    drvs = inputs["drvs"]
    if not isinstance(drvs, dict):
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            f"expected `inputs.drvs` in derivation `{drv_path}` to be an object",
        )
    return _validated_path_keys(
        drvs,
        f"`inputs.drvs` in derivation `{drv_path}`",
        NIX_DERIVATION_SHOW_JSON,
    )


def nix_derivation_input_src_paths(drv_path, drv_info):
    """Return validated direct source inputs from normalized derivation JSON."""
    inputs = _require_derivation_inputs(drv_path, drv_info)
    if "srcs" not in inputs:
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            f"missing `inputs.srcs` in derivation `{drv_path}`",
        )
    srcs = inputs["srcs"]
    if not isinstance(srcs, list):
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            f"expected `inputs.srcs` in derivation `{drv_path}` to be a list",
        )
    return _validated_path_values(
        srcs,
        f"`inputs.srcs` in derivation `{drv_path}`",
        NIX_DERIVATION_SHOW_JSON,
    )


def _require_derivation_inputs(drv_path, drv_info):
    """Return the validated modern derivation input object.

    Parsing derivation metadata only validates an optional ``inputs`` object
    because some callers use unrelated fields. Graph construction depends on
    the modern dependency schema, so this accessor requires ``inputs`` and the
    field-specific accessors require both ``inputs.drvs`` and ``inputs.srcs``.
    Real leaf derivations still expose those fields as empty containers.
    """
    if not isinstance(drv_info, dict):
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            f"expected derivation `{drv_path}` to be an object",
        )
    _reject_legacy_derivation_inputs(drv_path, drv_info)
    if "inputs" not in drv_info:
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            f"missing derivation inputs in `{drv_path}`",
        )
    inputs = drv_info["inputs"]
    if not isinstance(inputs, dict):
        raise InvalidNixJsonError(
            NIX_DERIVATION_SHOW_JSON,
            f"expected `inputs` in derivation `{drv_path}` to be an object",
        )
    return inputs


def normalize_nix_path_info(path_info, *, command=NIX_PATH_INFO_JSON):
    """Normalize and validate Nix path-info JSON to a path-indexed dictionary."""
    if isinstance(path_info, dict):
        normalized = {}
        for path, info in path_info.items():
            if not isinstance(path, str) or not path:
                raise InvalidNixJsonError(
                    command,
                    "expected path-info object keys to be non-empty strings",
                )
            if not isinstance(info, dict):
                raise InvalidNixJsonError(
                    command,
                    f"expected path-info record for `{path}` to be an object",
                )
            normalized[path] = info
        return normalized

    if isinstance(path_info, list):
        normalized = {}
        for index, info in enumerate(path_info):
            if not isinstance(info, dict):
                raise InvalidNixJsonError(
                    command,
                    f"expected path-info list item {index} to be an object",
                )
            path = info.get("path") or info.get("storePath")
            if not isinstance(path, str) or not path:
                raise InvalidNixJsonError(
                    command,
                    f"missing path string in path-info list item {index}",
                )
            normalized[path] = info
        return normalized

    raise InvalidNixJsonError(
        command,
        f"expected top-level object or list, got {type(path_info).__name__}",
    )


def nix_path_info_references(info, path, *, command=NIX_PATH_INFO_JSON):
    """Return validated path-info references for a store path."""
    if "references" not in info:
        raise InvalidNixJsonError(
            command,
            f"missing `references` in path-info for `{path}`",
        )
    references = info["references"]
    if not isinstance(references, list):
        raise InvalidNixJsonError(
            command,
            f"expected `references` in path-info for `{path}` to be a list",
        )
    for index, reference in enumerate(references):
        if not isinstance(reference, str) or not reference:
            raise InvalidNixJsonError(
                command,
                f"expected `references[{index}]` in path-info for `{path}` "
                "to be a non-empty string",
            )
    return references


def nix_path_info_deriver(info, path, *, command=NIX_PATH_INFO_JSON):
    """Return a validated path-info deriver value, or None when absent."""
    deriver = info.get("deriver")
    if deriver is None or deriver == "":
        return None
    if not isinstance(deriver, str):
        raise InvalidNixJsonError(
            command,
            f"expected `deriver` in path-info for `{path}` to be a string or null",
        )
    return deriver


def nix_path_info_nar_hash(info, path, *, command=NIX_PATH_INFO_JSON):
    """Return a validated path-info NAR hash."""
    nar_hash = info.get("narHash")
    if not isinstance(nar_hash, str) or not nar_hash:
        raise InvalidNixJsonError(
            command,
            f"missing `narHash` string in path-info for `{path}`",
        )
    return nar_hash


def _validated_path_keys(paths, owner, command):
    validated = []
    for path in paths:
        if not isinstance(path, str) or not path:
            raise InvalidNixJsonError(
                command,
                f"expected keys in {owner} to be non-empty strings",
            )
        validated.append(path)
    return validated


def _validated_path_values(paths, owner, command):
    validated = []
    for index, path in enumerate(paths):
        if not isinstance(path, str) or not path:
            raise InvalidNixJsonError(
                command,
                f"expected paths in {owner} to be non-empty strings "
                f"(invalid index {index})",
            )
        validated.append(path)
    return validated
