#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Python script that generates SLSA v1.0 provenance file for a nix target"""

import argparse
import base64
import binascii
import errno
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from common.log import LOG, set_log_verbosity
from common.nix_utils import parse_nix_derivation_show
from common.proc import exec_cmd, nix_cmd

HASH_SIZE_BYTES = {
    "blake3": 32,
    "md5": 16,
    "sha1": 20,
    "sha256": 32,
    "sha512": 64,
}
NIX32_ALPHABET = "0123456789abcdfghijklmnpqrsvwxyz"
NIX32_INDEX = {char: index for index, char in enumerate(NIX32_ALPHABET)}


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


def _canonical_hash_algo(hash_algo: str | None) -> str | None:
    """Normalize legacy hash algorithm labels to plain algorithm names."""
    if not hash_algo:
        return None
    return str(hash_algo).removeprefix("r:")


def _hash_size_bytes(hash_algo: str | None) -> int | None:
    """Return expected digest size for the given algorithm."""
    return HASH_SIZE_BYTES.get(_canonical_hash_algo(hash_algo))


def _decode_nix32(hash_value: str, size_bytes: int) -> bytes | None:
    """Decode nix base32 digest strings into raw bytes."""
    try:
        value = 0
        for char in hash_value:
            value = value * 32 + NIX32_INDEX[char]
    except KeyError:
        return None

    if value.bit_length() > size_bytes * 8:
        return None

    encoded_size = (len(hash_value) * 5 + 7) // 8
    raw = value.to_bytes(encoded_size, "little")
    return raw[:size_bytes].ljust(size_bytes, b"\0")


def _decode_hash_bytes(hash_value: str, hash_algo: str) -> bytes | None:
    """Decode known Nix hash encodings into raw bytes."""
    size_bytes = _hash_size_bytes(hash_algo)
    if size_bytes is None:
        return None

    if re.fullmatch(rf"[0-9a-f]{{{size_bytes * 2}}}", hash_value):
        return bytes.fromhex(hash_value)

    if len(hash_value) == (size_bytes * 8 + 4) // 5:
        decoded = _decode_nix32(hash_value, size_bytes)
        if decoded is not None:
            return decoded

    padding = "=" * (-len(hash_value) % 4)
    try:
        decoded = base64.b64decode(hash_value + padding, validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(decoded) != size_bytes:
        return None
    return decoded


def _split_hash_value(
    hash_value: str, hash_algo: str | None = None
) -> tuple[str | None, str]:
    """Split a typed hash string into canonical algorithm and raw value."""
    hash_algo = _canonical_hash_algo(hash_algo)
    hash_value = str(hash_value).strip()

    if hash_algo:
        for separator in (":", "-"):
            legacy_prefix = f"r:{hash_algo}{separator}"
            if hash_value.startswith(legacy_prefix):
                return hash_algo, hash_value.removeprefix(legacy_prefix)
            prefix = f"{hash_algo}{separator}"
            if hash_value.startswith(prefix):
                return hash_algo, hash_value.removeprefix(prefix)

    match = re.match(
        r"^(?P<algo>(?:r:)?[A-Za-z0-9]+)(?P<sep>[:-])(?P<rest>.+)$", hash_value
    )
    if match:
        return _canonical_hash_algo(match.group("algo")), match.group("rest")

    return hash_algo, hash_value


def _normalize_digest(
    hash_value: str | None, hash_algo: str | None = None
) -> dict | None:
    """Return digest in a canonical base16 representation."""
    if not hash_value:
        return None
    hash_value = str(hash_value).strip()
    if not hash_value:
        return None

    hash_algo, raw_hash_value = _split_hash_value(hash_value, hash_algo=hash_algo)
    if not hash_algo:
        return None

    decoded = _decode_hash_bytes(raw_hash_value, hash_algo)
    if decoded is None:
        return None
    return {hash_algo: decoded.hex()}


def _output_digest(data: dict | None) -> dict | None:
    """Return digest from derivation output metadata when available."""
    if not isinstance(data, dict):
        return None
    hash_value = data.get("hash")
    if not hash_value:
        return None
    return _normalize_digest(hash_value, hash_algo=data.get("hashAlgo"))


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

    LOG.info("Parsing derivation outputs")

    env = env or {}
    subjects = []
    for name, data in outputs.items():
        output_path = _output_path(name, data, env)
        subject = {"name": name}
        output_digest = _output_digest(data)
        if output_path:
            subject["uri"] = output_path
        if output_digest is not None:
            subject["digest"] = output_digest
            LOG.info(
                "Using derivation metadata hash for fixed-output output '%s'", name
            )
        elif output_path:
            store_hash = exec_cmd(
                ["nix-store", "--query", "--hash", output_path],
                raise_on_error=False,
            )
            if store_hash is None:
                LOG.warning(
                    "Derivation output '%s' was not found in the nix store, "
                    "assuming it was not built.",
                    name,
                )
                continue
            digest = _normalize_digest(store_hash.stdout.strip())
            if digest is None:
                LOG.warning(
                    "Cannot normalize nix-store hash for derivation output '%s'", name
                )
                continue
            subject["digest"] = digest
        else:
            LOG.warning(
                "Cannot determine path or digest for derivation output '%s'", name
            )
            continue

        subjects.append(subject)

    return subjects


def query_store_hashes(paths: list[str]) -> list[str]:
    """Query store hashes, splitting the request when argv would exceed OS limits."""

    if not paths:
        return []

    try:
        return exec_cmd(["nix-store", "--query", "--hash", *paths]).stdout.split()
    except OSError as error:
        if error.errno != errno.E2BIG or len(paths) == 1:
            raise
        midpoint = len(paths) // 2
        return query_store_hashes(paths[:midpoint]) + query_store_hashes(
            paths[midpoint:]
        )


def _output_path(name: str, output: dict | None, env: dict | None = None) -> str | None:
    """Return the resolved absolute output path from outputs or env."""
    if isinstance(output, dict) and output.get("path"):
        return output["path"]
    env = env or {}
    return env.get(name)


def _derivation_outputs_by_path(infos: dict) -> dict[str, tuple[dict, dict]]:
    """Index derivation info by absolute output path."""
    outputs_by_path = {}
    for info in infos.values():
        if not isinstance(info, dict):
            continue
        outputs = info.get("outputs")
        if not isinstance(outputs, dict):
            continue
        env = info.get("env")
        for name, output in outputs.items():
            output_path = _output_path(name, output, env)
            if output_path:
                outputs_by_path[output_path] = (info, output)
    return outputs_by_path


def _dependency_package(
    drv: str, output_hash: str, infos: dict, outputs_by_path: dict
) -> dict | None:
    """Create a dependency package entry with a normalized digest."""
    info = infos.get(drv)
    output_info = outputs_by_path.get(drv)
    if output_info:
        info = output_info[0]
    digest = _output_digest(output_info[1]) if output_info else None
    if digest is None:
        digest = _normalize_digest(output_hash)
    if digest is None and ":" in output_hash:
        hash_type, hash_value = output_hash.split(":", 1)
        LOG.warning(
            "Falling back to non-normalized digest for dependency '%s': %s",
            drv,
            output_hash,
        )
        digest = {hash_type: hash_value}
    if digest is None:
        LOG.warning("Cannot determine digest for dependency '%s'", drv)
        return None

    package = {
        "name": drv.split("-", 1)[-1].removesuffix(".drv"),
        "uri": drv,
        "digest": digest,
    }

    if info:
        package["name"] = info["name"]
        if version := info["env"].get("version"):
            package["annotations"] = {"version": version}
    return package


def get_dependencies(drv_path: str, recursive: bool = False) -> list[dict]:
    """Get dependencies of derivation and parse them into ResourceDescriptors"""

    LOG.info("Querying derivation dependencies %s", "recursively" if recursive else "")

    depth = "--requisites" if recursive else "--references"

    references = exec_cmd(
        ["nix-store", "--query", depth, "--include-outputs", drv_path]
    ).stdout.split()
    hashes = query_store_hashes(references)
    infos = parse_nix_derivation_show(
        exec_cmd(["nix", "derivation", "show", "-r", drv_path]).stdout,
        store_path_hint=drv_path,
    )
    outputs_by_path = _derivation_outputs_by_path(infos)

    dependencies = []
    for drv, output_hash in zip(references, hashes):
        LOG.debug("Creating dependency entry for %s", drv)
        package = _dependency_package(drv, output_hash, infos, outputs_by_path)
        if package is not None:
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

    cmd = nix_cmd("derivation", "show", target)
    drv_json = parse_nix_derivation_show(exec_cmd(cmd).stdout, store_path_hint=target)
    drv_path = next(iter(drv_json))
    drv_json = drv_json[drv_path]

    LOG.info("Resolved derivation path is '%s'", drv_path)

    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": get_subjects(drv_json["outputs"], env=drv_json.get("env")),
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
