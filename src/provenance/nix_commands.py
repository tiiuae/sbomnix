# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Nix command helpers for provenance generation."""

import subprocess

from common.errors import NixCommandError


def exec_required_nix_command(cmd, exec_cmd_fn):
    """Run a required Nix command and raise a user-facing error on failure."""
    try:
        return exec_cmd_fn(cmd)
    except subprocess.CalledProcessError as error:
        raise NixCommandError(
            cmd,
            stderr=error.stderr,
            stdout=error.stdout,
        ) from None
