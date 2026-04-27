# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for deriving in-toto subjects from nix outputs."""

from dataclasses import dataclass

from common.log import LOG, LOG_VERBOSE
from common.proc import exec_cmd
from provenance.digests import normalize_digest, output_digest


def output_path(name, output, env=None):
    """Return the resolved absolute output path from outputs or env."""
    if isinstance(output, dict) and output.get("path"):
        return output["path"]
    env = env or {}
    return env.get(name)


@dataclass
class SubjectHooks:
    """Injectable helpers used by ``get_subjects``."""

    exec_cmd_fn: object = None
    normalize_digest_fn: object = None
    output_digest_fn: object = None
    output_path_fn: object = None
    log: object = LOG

    def __post_init__(self):
        if self.exec_cmd_fn is None:
            self.exec_cmd_fn = exec_cmd
        if self.normalize_digest_fn is None:
            self.normalize_digest_fn = normalize_digest
        if self.output_digest_fn is None:
            self.output_digest_fn = output_digest
        if self.output_path_fn is None:
            self.output_path_fn = output_path


def get_subjects(outputs, env=None, hooks=None):
    """Parse derivation outputs into in-toto subjects."""
    hooks = SubjectHooks() if hooks is None else hooks

    hooks.log.log(LOG_VERBOSE, "Parsing derivation outputs")

    env = env or {}
    subjects = []
    for name, data in outputs.items():
        resolved_output_path = hooks.output_path_fn(name, data, env)
        subject = {"name": name}
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
            store_hash = hooks.exec_cmd_fn(
                ["nix-store", "--query", "--hash", resolved_output_path],
                raise_on_error=False,
            )
            if store_hash is None:
                hooks.log.warning(
                    "Derivation output '%s' was not found in the nix store, "
                    "assuming it was not built.",
                    name,
                )
                continue
            digest = hooks.normalize_digest_fn(store_hash.stdout.strip())
            if digest is None:
                hooks.log.warning(
                    "Cannot normalize nix-store hash for derivation output '%s'",
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
