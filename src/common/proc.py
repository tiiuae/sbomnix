# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared subprocess and nix command helpers."""

import os
import shlex
import subprocess
from shutil import which

from common.errors import CommandNotFoundError, InvalidNixArtifactError
from common.log import LOG, LOG_VERBOSE


def exec_cmd(cmd, raise_on_error=True, return_error=False, log_error=True, stdout=None):
    """Run shell command `cmd`."""
    if isinstance(cmd, (str, bytes, os.PathLike)):
        raise TypeError("cmd must be an argv sequence, not a string-like value")
    cmd = [os.fspath(part) for part in cmd]
    command_str = shlex.join(cmd)
    LOG.debug("Running: %s", command_str)
    try:
        if stdout:
            ret = subprocess.run(cmd, encoding="utf-8", check=True, stdout=stdout)
        else:
            ret = subprocess.run(cmd, capture_output=True, encoding="utf-8", check=True)
        return ret
    except subprocess.CalledProcessError as error:
        if log_error:
            LOG.error(
                "Error running shell command:\n cmd:   '%s'\n stdout: %s\n stderr: %s",
                command_str,
                error.stdout,
                error.stderr,
            )
        if raise_on_error:
            raise error
        if return_error:
            return error
        return None


def exit_unless_command_exists(name, *, which_fn=None):
    """Raise if `name` is not an executable in PATH."""
    which_fn = which if which_fn is None else which_fn
    name_is_in_path = which_fn(name) is not None
    if not name_is_in_path:
        raise CommandNotFoundError(name)


def exit_unless_nix_artifact(path, force_realise=False, *, exec_cmd_fn=None, log=None):
    """
    Raise if `path` is not a nix artifact. If `force_realise` is True, run the
    nix-store-query command with `--force-realise` realising the `path`
    argument before running query.
    """
    exec_cmd_fn = exec_cmd if exec_cmd_fn is None else exec_cmd_fn
    log = LOG if log is None else log

    log.debug("force_realize: %s", force_realise)
    if force_realise:
        log.log(LOG_VERBOSE, "Try force-realising store-path '%s'", path)
        cmd = ["nix-store", "-qf", path]
    else:
        cmd = ["nix-store", "-q", path]
    try:
        exec_cmd_fn(cmd)
        return
    except subprocess.CalledProcessError:
        raise InvalidNixArtifactError(path) from None


def nix_cmd(*args, impure=False):
    """Build argv for nix commands that require flakes + nix-command support."""
    cmd = [
        "nix",
        *args,
        "--extra-experimental-features",
        "flakes",
        "--extra-experimental-features",
        "nix-command",
    ]
    if impure:
        cmd.append("--impure")
    return cmd
