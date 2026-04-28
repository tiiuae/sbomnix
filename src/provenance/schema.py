# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for assembling provenance documents."""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from common.log import LOG, LOG_VERBOSE
from common.nix_utils import parse_nix_derivation_show
from common.proc import exec_cmd, nix_cmd
from provenance.dependencies import get_dependencies
from provenance.subjects import get_subjects

JsonDict = dict[str, Any]
HookFn = Callable[..., Any]


class ProvenanceMetadata(Protocol):
    """Build metadata fields consumed by provenance schema assembly."""

    build_type: str
    builder_id: str
    invocation_id: str
    build_begin_ts: str
    build_finished_ts: str
    external_parameters: str
    internal_parameters: str


def get_external_parameters(metadata: ProvenanceMetadata) -> JsonDict:
    """Get externalParameters from env variable."""
    params = json.loads(metadata.external_parameters or "{}")
    return {key: value for key, value in params.items() if value}


def get_internal_parameters(metadata: ProvenanceMetadata) -> JsonDict:
    """Get internalParameters from env variable."""
    params = json.loads(metadata.internal_parameters or "{}")
    return {key: value for key, value in params.items() if value}


def timestamp(unix_time: str) -> str:
    """Turn unix timestamp into RFC 3339 format."""
    if not unix_time:
        return ""

    dtime = datetime.fromtimestamp(
        int(unix_time),
        tz=timezone.utc,
    )

    return dtime.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-4] + "Z"


@dataclass
class SchemaHooks:
    """Injectable helpers used by provenance schema assembly."""

    exec_cmd_fn: HookFn = exec_cmd
    nix_cmd_fn: HookFn = nix_cmd
    parse_nix_derivation_show_fn: HookFn = parse_nix_derivation_show
    get_subjects_fn: HookFn = get_subjects
    get_dependencies_fn: HookFn = get_dependencies
    get_external_parameters_fn: HookFn = get_external_parameters
    get_internal_parameters_fn: HookFn = get_internal_parameters
    timestamp_fn: HookFn = timestamp
    log: logging.Logger = LOG


def provenance_document(
    target: str,
    metadata: ProvenanceMetadata,
    recursive: bool = False,
    hooks: SchemaHooks | None = None,
) -> JsonDict:
    """Create the provenance file."""
    hooks = SchemaHooks() if hooks is None else hooks

    hooks.log.info("Generating provenance file for '%s'", target)

    cmd = hooks.nix_cmd_fn("derivation", "show", target)
    drv_json = hooks.parse_nix_derivation_show_fn(
        hooks.exec_cmd_fn(cmd).stdout,
        store_path_hint=target,
    )
    drv_path = next(iter(drv_json))
    drv_json = drv_json[drv_path]

    hooks.log.log(LOG_VERBOSE, "Resolved derivation path is '%s'", drv_path)

    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": hooks.get_subjects_fn(drv_json["outputs"], env=drv_json.get("env")),
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": metadata.build_type,
                "externalParameters": hooks.get_external_parameters_fn(metadata),
                "internalParameters": hooks.get_internal_parameters_fn(metadata),
                "resolvedDependencies": hooks.get_dependencies_fn(drv_path, recursive),
            },
            "runDetails": {
                "builder": {
                    "id": metadata.builder_id,
                    "builderDependencies": [],
                    "version": {},
                },
                "metadata": {
                    "invocationId": metadata.invocation_id,
                    "startedOn": hooks.timestamp_fn(metadata.build_begin_ts),
                    "finishedOn": hooks.timestamp_fn(metadata.build_finished_ts),
                },
                "byproducts": [],
            },
        },
    }
