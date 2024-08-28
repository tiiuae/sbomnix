#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Python script that generates SLSA v1.0 provenance file for a nix target"""

import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from common.utils import LOG, exec_cmd, set_log_verbosity


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


def get_subjects(outputs: dict) -> list[dict]:
    """Parse derivation outputs into in-toto subjects"""

    LOG.info("Parsing derivation outputs")

    subjects = []
    for name, data in outputs.items():
        subject = {
            "name": name,
            "uri": data["path"],
        }
        store_hash = exec_cmd(
            ["nix-store", "--query", "--hash", data["path"]],
            raise_on_error=False,
        )
        if store_hash is None:
            LOG.warning(
                "Derivation output '%s' was not found in the nix store, "
                "assuming it was not built.",
                name,
            )
        else:
            hash_type, hash_value = store_hash.stdout.strip().split(":")
            subject["digest"] = {hash_type: hash_value}
            subjects.append(subject)

    return subjects


def get_dependencies(drv_path: str, recursive: bool = False) -> list[dict]:
    """Get dependencies of derivation and parse them into ResourceDescriptors"""

    LOG.info("Querying derivation dependencies %s", "recursively" if recursive else "")

    depth = "--requisites" if recursive else "--references"

    references = exec_cmd(
        ["nix-store", "--query", depth, "--include-outputs", drv_path]
    ).stdout.split()
    hashes = exec_cmd(["nix-store", "--query", "--hash"] + references).stdout.split()
    infos = json.loads(exec_cmd(["nix", "derivation", "show", "-r", drv_path]).stdout)

    dependencies = []
    for drv, output_hash in zip(references, hashes):
        LOG.debug("Creating dependency entry for %s", drv)
        hash_type, hash_value = output_hash.split(":")

        package = {
            "name": drv.split("-", 1)[-1].removesuffix(".drv"),
            "uri": drv,
            "digest": {hash_type: hash_value},
        }

        info = infos.get(drv)
        if info:
            package["name"] = info["name"]
            if version := info["env"].get("version"):
                package["annotations"] = {"version": version}

        dependencies.append(package)

    return dependencies


def get_external_parameters(metadata: BuildMeta) -> dict:
    """Get externalParameters from env variable"""

    params = json.loads(metadata.external_parameters or "{}")

    # return only params with non-empty values
    return {k: v for k, v in params.items() if v}


def get_internal_parameters(metadata: BuildMeta) -> dict:
    """Get internalParameters from env variable"""

    params = json.loads(metadata.internal_parameters or "{}")

    # return only params with non-empty values
    return {k: v for k, v in params.items() if v}


def timestamp(unix_time: int | str | None) -> str:
    """Turn unix timestamp into RFC 3339 format"""

    if not unix_time:
        return ""

    dtime = datetime.fromtimestamp(
        int(unix_time),
        tz=timezone.utc,
    )

    return dtime.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-4] + "Z"


def provenance(target: str, metadata: BuildMeta, recursive: bool = False) -> dict:
    """Create the provenance file"""

    LOG.info("Generating provenance file for '%s'", target)

    exp = "--extra-experimental-features flakes "
    exp += "--extra-experimental-features nix-command"
    cmd = f"nix derivation show {target} {exp}"
    drv_json = json.loads(exec_cmd(cmd.split()).stdout)
    drv_path = next(iter(drv_json))
    drv_json = drv_json[drv_path]

    LOG.info("Resolved derivation path is '%s'", drv_path)

    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": get_subjects(drv_json["outputs"]),
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": metadata.build_type,
                "externalParameters": get_external_parameters(metadata),
                "internalParameters": get_internal_parameters(metadata),
                "resolvedDependencies": get_dependencies(drv_path, recursive),
            },
            "runDetails": {
                "builder": {
                    "id": metadata.builder_id,
                    "builderDependencies": [],
                    "version": {},
                },
                "metadata": {
                    "invocationId": metadata.invocation_id,
                    "startedOn": timestamp(metadata.build_begin_ts),
                    "finishedOn": timestamp(metadata.build_finished_ts),
                },
                "byproducts": [],
            },
        },
    }


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
