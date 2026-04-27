# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-instance-attributes

"""Helpers for assembling provenance documents."""

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from common.log import LOG, LOG_VERBOSE
from common.nix_utils import parse_nix_derivation_show
from common.proc import exec_cmd, nix_cmd
from provenance.dependencies import get_dependencies
from provenance.subjects import get_subjects


def get_external_parameters(metadata):
    """Get externalParameters from env variable."""
    params = json.loads(metadata.external_parameters or "{}")
    return {key: value for key, value in params.items() if value}


def get_internal_parameters(metadata):
    """Get internalParameters from env variable."""
    params = json.loads(metadata.internal_parameters or "{}")
    return {key: value for key, value in params.items() if value}


def timestamp(unix_time):
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

    exec_cmd_fn: object = None
    nix_cmd_fn: object = None
    parse_nix_derivation_show_fn: object = None
    get_subjects_fn: object = None
    get_dependencies_fn: object = None
    get_external_parameters_fn: object = None
    get_internal_parameters_fn: object = None
    timestamp_fn: object = None
    log: object = LOG

    def __post_init__(self):
        if self.exec_cmd_fn is None:
            self.exec_cmd_fn = exec_cmd
        if self.nix_cmd_fn is None:
            self.nix_cmd_fn = nix_cmd
        if self.parse_nix_derivation_show_fn is None:
            self.parse_nix_derivation_show_fn = parse_nix_derivation_show
        if self.get_subjects_fn is None:
            self.get_subjects_fn = get_subjects
        if self.get_dependencies_fn is None:
            self.get_dependencies_fn = get_dependencies
        if self.get_external_parameters_fn is None:
            self.get_external_parameters_fn = get_external_parameters
        if self.get_internal_parameters_fn is None:
            self.get_internal_parameters_fn = get_internal_parameters
        if self.timestamp_fn is None:
            self.timestamp_fn = timestamp


def provenance_document(target, metadata, recursive=False, hooks=None):
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
