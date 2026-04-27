#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Offline provenance tests that do not require CLI execution."""

import errno
import subprocess

from provenance import main as provenance_main


def test_provenance_hash_query_batches_on_e2big(monkeypatch):
    """Test provenance splits oversized nix-store hash queries and preserves order."""
    references = [f"/nix/store/hash-{idx}" for idx in range(5)]
    calls = []

    def fake_exec_cmd(cmd, **_kwargs):
        if cmd[:3] == ["nix-store", "--query", "--hash"]:
            batch = cmd[3:]
            calls.append(batch)
            if len(batch) > 2:
                raise OSError(errno.E2BIG, "Argument list too long")
            hashes = "\n".join(
                f"sha256:hash-{path.rsplit('-', 1)[-1]}" for path in batch
            )
            return subprocess.CompletedProcess(cmd, 0, stdout=f"{hashes}\n", stderr="")
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(provenance_main, "exec_cmd", fake_exec_cmd)

    hashes = provenance_main.query_store_hashes(references)

    assert hashes == [f"sha256:hash-{idx}" for idx in range(5)]
    assert calls == [
        references,
        references[:2],
        references[2:],
        references[2:3],
        references[3:],
    ]
