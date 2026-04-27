#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Python script that generates SLSA v1.0 provenance file for a nix target"""

import argparse
import json
import os
from dataclasses import dataclass
from importlib import import_module

from common.log import LOG, set_log_verbosity
from common.nix_utils import parse_nix_derivation_show
from common.proc import exec_cmd, nix_cmd

provenance_dependencies = import_module("provenance.dependencies")
provenance_digests = import_module("provenance.digests")
provenance_schema = import_module("provenance.schema")
provenance_subjects = import_module("provenance.subjects")


@dataclass
class BuildMeta:
    """Dataclass for build metadata"""

    build_type: str
    builder_id: str
    invocation_id: str
    build_begin_ts: str
    build_finished_ts: str
    external_parameters: str
    internal_parameters: str


_canonical_hash_algo = provenance_digests.canonical_hash_algo
_hash_size_bytes = provenance_digests.hash_size_bytes
_decode_nix32 = provenance_digests.decode_nix32
_decode_hash_bytes = provenance_digests.decode_hash_bytes
_split_hash_value = provenance_digests.split_hash_value


def _normalize_digest(
    hash_value: str | None, hash_algo: str | None = None
) -> dict | None:
    """Return digest in a canonical base16 representation."""
    return provenance_digests.normalize_digest(hash_value, hash_algo=hash_algo)


def _output_digest(data: dict | None) -> dict | None:
    """Return digest from derivation output metadata when available."""
    return provenance_digests.output_digest(data, normalize_digest_fn=_normalize_digest)


def get_env_metadata():
    """Read build metadata from env variables"""

    # these need to be in the same order as the fields in BuildMeta definition
    env_vars = [
        "PROVENANCE_BUILD_TYPE",
        "PROVENANCE_BUILDER_ID",
        "PROVENANCE_INVOCATION_ID",
        "PROVENANCE_TIMESTAMP_BEGIN",
        "PROVENANCE_TIMESTAMP_FINISHED",
        "PROVENANCE_EXTERNAL_PARAMS",
        "PROVENANCE_INTERNAL_PARAMS",
    ]

    values = [os.environ.get(name, "") for name in env_vars]

    LOG.info("Reading metadata from environment:")
    for name, value in zip(env_vars, values):
        LOG.info("| %s = %s", name, value)

    return BuildMeta(*values)


def get_subjects(outputs: dict, env: dict | None = None) -> list[dict]:
    """Parse derivation outputs into in-toto subjects"""
    return provenance_subjects.get_subjects(
        outputs,
        env=env,
        hooks=provenance_subjects.SubjectHooks(
            exec_cmd_fn=exec_cmd,
            normalize_digest_fn=_normalize_digest,
            output_digest_fn=_output_digest,
            output_path_fn=_output_path,
            log=LOG,
        ),
    )


def query_store_hashes(paths: list[str]) -> list[str]:
    """Query store hashes, splitting the request when argv would exceed OS limits."""
    return provenance_dependencies.query_store_hashes(
        paths,
        hooks=provenance_dependencies.DependencyHooks(
            exec_cmd_fn=exec_cmd,
        ),
    )


def _output_path(name: str, output: dict | None, env: dict | None = None) -> str | None:
    """Return the resolved absolute output path from outputs or env."""
    return provenance_subjects.output_path(name, output, env=env)


def _derivation_outputs_by_path(infos: dict) -> dict[str, tuple[dict, dict]]:
    """Index derivation info by absolute output path."""
    return provenance_dependencies.derivation_outputs_by_path(
        infos,
        hooks=provenance_dependencies.DependencyHooks(
            output_path_fn=_output_path,
        ),
    )


def _dependency_package(
    drv: str, output_hash: str, infos: dict, outputs_by_path: dict
) -> dict | None:
    """Create a dependency package entry with a normalized digest."""
    return provenance_dependencies.dependency_package(
        drv,
        output_hash,
        infos,
        outputs_by_path,
        hooks=provenance_dependencies.DependencyHooks(
            normalize_digest_fn=_normalize_digest,
            output_digest_fn=_output_digest,
            log=LOG,
        ),
    )


def get_dependencies(drv_path: str, recursive: bool = False) -> list[dict]:
    """Get dependencies of derivation and parse them into ResourceDescriptors"""
    return provenance_dependencies.get_dependencies(
        drv_path,
        recursive=recursive,
        hooks=provenance_dependencies.DependencyHooks(
            exec_cmd_fn=exec_cmd,
            query_store_hashes_fn=query_store_hashes,
            parse_nix_derivation_show_fn=parse_nix_derivation_show,
            normalize_digest_fn=_normalize_digest,
            output_digest_fn=_output_digest,
            output_path_fn=_output_path,
            log=LOG,
        ),
    )


def get_external_parameters(metadata: BuildMeta) -> dict:
    """Get externalParameters from env variable"""
    return provenance_schema.get_external_parameters(metadata)


def get_internal_parameters(metadata: BuildMeta) -> dict:
    """Get internalParameters from env variable"""
    return provenance_schema.get_internal_parameters(metadata)


def timestamp(unix_time: int | str | None) -> str:
    """Turn unix timestamp into RFC 3339 format"""
    return provenance_schema.timestamp(unix_time)


def provenance(target: str, metadata: BuildMeta, recursive: bool = False) -> dict:
    """Create the provenance file"""
    return provenance_schema.provenance_document(
        target,
        metadata,
        recursive=recursive,
        hooks=provenance_schema.SchemaHooks(
            exec_cmd_fn=exec_cmd,
            nix_cmd_fn=nix_cmd,
            parse_nix_derivation_show_fn=parse_nix_derivation_show,
            get_subjects_fn=get_subjects,
            get_dependencies_fn=get_dependencies,
            get_external_parameters_fn=get_external_parameters,
            get_internal_parameters_fn=get_internal_parameters,
            timestamp_fn=timestamp,
            log=LOG,
        ),
    )


def getargs():
    """Parse command line arguments"""

    parser = argparse.ArgumentParser(
        prog="nix-provenance",
        description="Get SLSA v1.0 provenance file from nix flake or derivation",
    )
    parser.add_argument(
        "target",
        help="Flake reference or derivation path",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Resolve every dependency recursively",
    )
    parser.add_argument(
        "--out",
        help="Path to file where provenance should be saved",
        default=os.environ.get("PROVENANCE_OUTPUT_FILE"),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Set the debug verbosity level between 0-3 (default: --verbose=1).",
        type=int,
        default=1,
    )

    return parser.parse_args()


def main():
    """main entry point"""

    args = getargs()
    set_log_verbosity(args.verbose)

    build_metadata = get_env_metadata()

    schema = provenance(args.target, build_metadata, recursive=args.recursive)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as filepath:
            LOG.info("Writing provenance file into '%s'", args.out)
            filepath.write(json.dumps(schema, indent=2))
    else:
        print(json.dumps(schema, indent=2))


if __name__ == "__main__":
    main()
