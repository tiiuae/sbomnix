# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared subprocess and nix command helpers."""

import logging
import os
import shlex
import subprocess
from collections.abc import Callable, Sequence
from shutil import which
from typing import IO, Literal, overload

from common.errors import CommandNotFoundError, InvalidNixArtifactError
from common.log import LOG, LOG_VERBOSE

CommandPart = str | os.PathLike[str]
ExecCmdResult = subprocess.CompletedProcess[str] | subprocess.CalledProcessError | None
ExecCmdFn = Callable[..., ExecCmdResult]


@overload
def exec_cmd(
    cmd: Sequence[CommandPart],
    raise_on_error: Literal[True] = True,
    return_error: bool = False,
    log_error: bool = True,
    stdout: IO[str] | None = None,
) -> subprocess.CompletedProcess[str]: ...


@overload
def exec_cmd(
    cmd: Sequence[CommandPart],
    raise_on_error: Literal[False],
    return_error: Literal[True],
    log_error: bool = True,
    stdout: IO[str] | None = None,
) -> subprocess.CompletedProcess[str] | subprocess.CalledProcessError | None: ...


@overload
def exec_cmd(
    cmd: Sequence[CommandPart],
    raise_on_error: Literal[False],
    return_error: Literal[False] = False,
    log_error: bool = True,
    stdout: IO[str] | None = None,
) -> subprocess.CompletedProcess[str] | None: ...


def exec_cmd(
    cmd: Sequence[CommandPart],
    raise_on_error: bool = True,
    return_error: bool = False,
    log_error: bool = True,
    stdout: IO[str] | None = None,
) -> ExecCmdResult:
    """Run shell command `cmd`."""
    if isinstance(cmd, (str, bytes, os.PathLike)):
        raise TypeError("cmd must be an argv sequence, not a string-like value")
    argv = [os.fspath(part) for part in cmd]
    command_str = shlex.join(argv)
    LOG.debug("Running: %s", command_str)
    try:
        if stdout:
            ret = subprocess.run(argv, encoding="utf-8", check=True, stdout=stdout)
        else:
            ret = subprocess.run(
                argv,
                capture_output=True,
                encoding="utf-8",
                check=True,
            )
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


def exit_unless_command_exists(
    name: str,
    *,
    which_fn: Callable[[str], str | None] | None = None,
) -> None:
    """Raise if `name` is not an executable in PATH."""
    which_fn = which if which_fn is None else which_fn
    name_is_in_path = which_fn(name) is not None
    if not name_is_in_path:
        raise CommandNotFoundError(name)


def exit_unless_nix_artifact(
    path: str,
    force_realise: bool = False,
    *,
    exec_cmd_fn: ExecCmdFn | None = None,
    log: logging.Logger | None = None,
) -> None:
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


def nix_cmd(*args: str, impure: bool = False) -> list[str]:
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
