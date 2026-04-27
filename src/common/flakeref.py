# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Flakeref resolution helpers."""

import pathlib
import re

from common.errors import FlakeRefRealisationError, FlakeRefResolutionError
from common.log import LOG
from common.proc import exec_cmd, nix_cmd


def try_resolve_flakeref(
    flakeref,
    force_realise=False,
    impure=False,
    *,
    exec_cmd_fn=None,
    log=None,
):
    """
    Resolve flakeref to out-path, force-realising the output if
    ``force_realise`` is True.
    """
    exec_cmd_fn = exec_cmd if exec_cmd_fn is None else exec_cmd_fn
    log = LOG if log is None else log

    log.info("Evaluating '%s'", flakeref)
    cmd = nix_cmd("eval", "--raw", flakeref, impure=impure)
    ret = exec_cmd_fn(cmd, raise_on_error=False, return_error=True, log_error=False)
    if ret is None or ret.returncode != 0:
        if _looks_like_flakeref(flakeref):
            raise FlakeRefResolutionError(flakeref, ret.stderr if ret else "")
        log.debug("not a flakeref: '%s'", flakeref)
        return None
    nixpath = ret.stdout.strip()
    log.debug("flakeref='%s' maps to path='%s'", flakeref, nixpath)
    if not force_realise:
        return nixpath
    log.info("Try force-realising flakeref '%s'", flakeref)
    cmd = nix_cmd("build", "--no-link", flakeref, impure=impure)
    ret = exec_cmd_fn(cmd, raise_on_error=False, return_error=True, log_error=False)
    if ret is None or ret.returncode != 0:
        raise FlakeRefRealisationError(flakeref, ret.stderr if ret else "")
    return nixpath


def _looks_like_flakeref(flakeref):
    """Return true if the input is likely intended as a flake reference."""
    looks_like = False
    if flakeref:
        path = pathlib.Path(flakeref)
        if path.exists():
            looks_like = path.is_dir() and (path / "flake.nix").exists()
        else:
            looks_like = (
                flakeref.startswith("nixpkgs=")
                or "#" in flakeref
                or "?" in flakeref
                or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", flakeref) is not None
            )
    return looks_like
