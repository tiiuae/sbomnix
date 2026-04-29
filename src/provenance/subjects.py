# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for deriving in-toto subjects from nix outputs."""

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable

from common.log import LOG, LOG_VERBOSE
from common.proc import ExecCmdFn, exec_cmd
from provenance.digests import normalize_digest, output_digest
from provenance.path_info import nar_hash_for_path, query_path_info

Digest = dict[str, str]
Subject = dict[str, Any]
OutputPathFn = Callable[[str, Any, Mapping[str, str] | None], str | None]
OutputDigestFn = Callable[[Any], Digest | None]
NormalizeDigestFn = Callable[..., Digest | None]


def output_path(
    name: str,
    output: Any,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """Return the resolved absolute output path from outputs or env."""
    if isinstance(output, dict) and output.get("path"):
        return str(output["path"])
    env = env or {}
    return env.get(name)


@dataclass
class SubjectHooks:
    """Injectable helpers used by ``get_subjects``."""

    exec_cmd_fn: ExecCmdFn = exec_cmd
    normalize_digest_fn: NormalizeDigestFn = normalize_digest
    output_digest_fn: OutputDigestFn = output_digest
    output_path_fn: OutputPathFn = output_path
    log: logging.Logger = LOG


def get_subjects(
    outputs: Mapping[str, Any],
    env: Mapping[str, str] | None = None,
    hooks: SubjectHooks | None = None,
) -> list[Subject]:
    """Parse derivation outputs into in-toto subjects."""
    hooks = SubjectHooks() if hooks is None else hooks

    hooks.log.log(LOG_VERBOSE, "Parsing derivation outputs")

    env = env or {}
    subjects: list[Subject] = []
    for name, data in outputs.items():
        resolved_output_path = hooks.output_path_fn(name, data, env)
        subject: Subject = {"name": name}
        resolved_output_digest = hooks.output_digest_fn(data)
        if resolved_output_path:
            subject["uri"] = resolved_output_path
        if resolved_output_digest is not None:
            subject["digest"] = resolved_output_digest
            hooks.log.log(
                LOG_VERBOSE,
                "Using derivation metadata hash for fixed-output output '%s'",
                name,
            )
        elif resolved_output_path:
            path_infos = query_path_info(
                [resolved_output_path],
                exec_cmd_fn=hooks.exec_cmd_fn,
                raise_on_error=False,
            )
            if path_infos is None or resolved_output_path not in path_infos:
                hooks.log.warning(
                    "Derivation output '%s' was not found in the nix store, "
                    "assuming it was not built.",
                    name,
                )
                continue
            digest = hooks.normalize_digest_fn(
                nar_hash_for_path(path_infos, resolved_output_path)
            )
            if digest is None:
                hooks.log.warning(
                    "Cannot normalize NAR hash for derivation output '%s'",
                    name,
                )
                continue
            subject["digest"] = digest
        else:
            hooks.log.warning(
                "Cannot determine path or digest for derivation output '%s'",
                name,
            )
            continue

        subjects.append(subject)

    return subjects
