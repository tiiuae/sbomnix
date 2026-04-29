#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Offline provenance tests that do not require CLI execution."""

import errno
import json
import subprocess

from provenance.path_info import query_path_hashes


def _path_info_paths(cmd):
    assert cmd[:5] == ["nix", "path-info", "--json", "--json-format", "1"]
    args = cmd[5:]
    if "--extra-experimental-features" in args:
        args = args[: args.index("--extra-experimental-features")]
    return args


def test_provenance_hash_query_batches_on_e2big():
    """Test provenance splits oversized path-info hash queries and preserves order."""
    references = [f"/nix/store/hash-{idx}" for idx in range(5)]
    calls = []

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[:5] == ["nix", "path-info", "--json", "--json-format", "1"]:
            batch = _path_info_paths(cmd)
            calls.append(batch)
            if len(batch) > 2:
                raise OSError(errno.E2BIG, "Argument list too long")
            path_info = {
                path: {"narHash": f"sha256:hash-{path.rsplit('-', 1)[-1]}"}
                for path in batch
            }
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=json.dumps(path_info),
                stderr="",
            )
        raise AssertionError(f"unexpected command: {cmd}")

    hashes = query_path_hashes(
        references,
        exec_cmd_fn=fake_exec_cmd,
    )

    assert hashes == [f"sha256:hash-{idx}" for idx in range(5)]
    assert calls == [
        references,
        references[:2],
        references[2:],
        references[2:3],
        references[3:],
    ]
