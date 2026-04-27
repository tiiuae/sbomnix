#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Python script that generates SLSA v1.0 provenance file for a nix target"""

import argparse
import json
import os
from dataclasses import dataclass

from common.cli_args import add_verbose_argument, add_version_argument
from common.log import LOG, set_log_verbosity
from common.nix_utils import parse_nix_derivation_show
from common.proc import exec_cmd, nix_cmd
from provenance.dependencies import DependencyHooks, get_dependencies
from provenance.digests import normalize_digest, output_digest
from provenance.schema import (
    SchemaHooks,
    get_external_parameters,
    get_internal_parameters,
    provenance_document,
    timestamp,
)
from provenance.subjects import SubjectHooks, get_subjects, output_path


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


def provenance(target: str, metadata: BuildMeta, recursive: bool = False) -> dict:
    """Create the provenance file"""
    return provenance_document(
        target,
        metadata,
        recursive=recursive,
        hooks=SchemaHooks(
            exec_cmd_fn=exec_cmd,
            nix_cmd_fn=nix_cmd,
            parse_nix_derivation_show_fn=parse_nix_derivation_show,
            get_subjects_fn=lambda outputs, env=None: get_subjects(
                outputs,
                env=env,
                hooks=SubjectHooks(
                    exec_cmd_fn=exec_cmd,
                    normalize_digest_fn=normalize_digest,
                    output_digest_fn=output_digest,
                    output_path_fn=output_path,
                    log=LOG,
                ),
            ),
            get_dependencies_fn=lambda drv_path, recursive=False: get_dependencies(
                drv_path,
                recursive=recursive,
                hooks=DependencyHooks(
                    exec_cmd_fn=exec_cmd,
                    parse_nix_derivation_show_fn=parse_nix_derivation_show,
                    normalize_digest_fn=normalize_digest,
                    output_digest_fn=output_digest,
                    output_path_fn=output_path,
                    log=LOG,
                ),
            ),
            get_external_parameters_fn=get_external_parameters,
            get_internal_parameters_fn=get_internal_parameters,
            timestamp_fn=timestamp,
            log=LOG,
        ),
    )


def getargs(args=None):
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
        "-o",
        "--out",
        help="Path to file where provenance should be saved",
        default=os.environ.get("PROVENANCE_OUTPUT_FILE"),
    )
    add_verbose_argument(parser)
    add_version_argument(parser)

    return parser.parse_args(args)


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
