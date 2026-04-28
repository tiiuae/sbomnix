# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Flakeref resolution helpers."""

import logging
import pathlib
import re

from common.errors import FlakeRefRealisationError, FlakeRefResolutionError
from common.log import LOG, LOG_VERBOSE
from common.nix_utils import parse_nix_derivation_show
from common.proc import ExecCmdFn, exec_cmd, nix_cmd

NIXOS_CONFIGURATION_TOPLEVEL_SUFFIX = ".config.system.build.toplevel"
_NIXOS_CONFIGURATION_PREFIX_RE = re.compile(
    r"^(?P<flake>.+)#nixosConfigurations\.(?P<rest>.+)$"
)
_UNQUOTED_ATTR_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_'-]+$")
_NIX_STRING_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


def try_resolve_flakeref(  # noqa: PLR0913
    flakeref: str,
    force_realise: bool = False,
    impure: bool = False,
    derivation: bool = False,
    *,
    exec_cmd_fn: ExecCmdFn | None = None,
    log: logging.Logger | None = None,
) -> str | None:
    """
    Resolve flakeref to out-path, force-realising the output if
    ``force_realise`` is True.
    """
    exec_cmd_fn = exec_cmd if exec_cmd_fn is None else exec_cmd_fn
    log = LOG if log is None else log

    looks_like_flakeref = _looks_like_flakeref(flakeref)
    if derivation and not force_realise and looks_like_flakeref:
        log.info("Evaluating flakeref '%s'", flakeref)
        cmd = nix_cmd("derivation", "show", flakeref, impure=impure)
        ret = exec_cmd_fn(cmd, raise_on_error=False, return_error=True, log_error=False)
        if ret is None or ret.returncode != 0:
            raise FlakeRefResolutionError(flakeref, ret.stderr if ret else "")
        drv_paths = parse_nix_derivation_show(ret.stdout)
        drv_path = next(iter(drv_paths), "")
        if not drv_path:
            raise FlakeRefResolutionError(
                flakeref,
                "nix derivation show returned no derivation path",
            )
        log.debug("flakeref='%s' maps to derivation='%s'", flakeref, drv_path)
        return drv_path

    if force_realise and looks_like_flakeref:
        log.info("Realising flakeref '%s'", flakeref)
        cmd = nix_cmd(
            "build",
            "--no-link",
            "--print-out-paths",
            flakeref,
            impure=impure,
        )
        ret = exec_cmd_fn(cmd, raise_on_error=False, return_error=True, log_error=False)
        if ret is None or ret.returncode != 0:
            raise FlakeRefRealisationError(flakeref, ret.stderr if ret else "")
        nixpath = _first_output_path(ret.stdout)
        if not nixpath:
            raise FlakeRefRealisationError(
                flakeref,
                "nix build returned no output path",
            )
        log.debug("flakeref='%s' maps to path='%s'", flakeref, nixpath)
        return nixpath

    if looks_like_flakeref:
        log.info("Evaluating flakeref '%s'", flakeref)
    else:
        log.log(LOG_VERBOSE, "Evaluating '%s'", flakeref)
    cmd = nix_cmd("eval", "--raw", flakeref, impure=impure)
    ret = exec_cmd_fn(cmd, raise_on_error=False, return_error=True, log_error=False)
    if ret is None or ret.returncode != 0:
        if looks_like_flakeref:
            raise FlakeRefResolutionError(flakeref, ret.stderr if ret else "")
        log.debug("not a flakeref: '%s'", flakeref)
        return None
    nixpath = ret.stdout.strip()
    log.debug("flakeref='%s' maps to path='%s'", flakeref, nixpath)
    if not force_realise:
        return nixpath
    log.info("Realising flakeref '%s'", flakeref)
    cmd = nix_cmd("build", "--no-link", flakeref, impure=impure)
    ret = exec_cmd_fn(cmd, raise_on_error=False, return_error=True, log_error=False)
    if ret is None or ret.returncode != 0:
        raise FlakeRefRealisationError(flakeref, ret.stderr if ret else "")
    return nixpath


def _first_output_path(stdout: str) -> str:
    """Return the first output path printed by ``nix build --print-out-paths``."""
    return next((line.strip() for line in stdout.splitlines() if line.strip()), "")


def parse_nixos_configuration_ref(
    flakeref: str,
    *,
    suffix: str = "",
) -> tuple[str, str] | None:
    """
    Parse ``<flake>#nixosConfigurations.<name><suffix>``.

    ``name`` may be either an unquoted attr segment or a quoted segment such as
    ``"host.example.com"``. The returned name is decoded and safe to re-quote.
    """
    match = _NIXOS_CONFIGURATION_PREFIX_RE.match(flakeref or "")
    if not match:
        return None
    parsed = _consume_nix_attr_segment(match.group("rest"))
    if not parsed:
        return None
    name, tail = parsed
    if tail != suffix:
        return None
    return match.group("flake"), name


def quote_nix_attr_segment(name: str) -> str:
    """Return a safely quoted Nix attr path segment."""
    escaped = []
    idx = 0
    while idx < len(name):
        if name.startswith("${", idx):
            escaped.append(r"\${")
            idx += 2
            continue
        char = name[idx]
        if char == '"':
            escaped.append('\\"')
        elif char == "\\":
            escaped.append("\\\\")
        elif char == "\n":
            escaped.append("\\n")
        elif char == "\r":
            escaped.append("\\r")
        elif char == "\t":
            escaped.append("\\t")
        else:
            escaped.append(char)
        idx += 1
    return '"' + "".join(escaped) + '"'


def _consume_nix_attr_segment(value: str) -> tuple[str, str] | None:
    if not value:
        return None
    if value.startswith('"'):
        end = _find_quoted_attr_end(value)
        if end is None:
            return None
        raw_segment = value[: end + 1]
        segment = _decode_nix_quoted_attr_segment(raw_segment)
        if segment is None:
            return None
        return segment, value[end + 1 :]

    segment, separator, tail = value.partition(".")
    if not segment or not _UNQUOTED_ATTR_SEGMENT_RE.match(segment):
        return None
    return segment, f"{separator}{tail}" if separator else ""


def _decode_nix_quoted_attr_segment(value: str) -> str | None:
    end = len(value) - 1
    if len(value) < 2 or value[0] != '"' or value[end] != '"':
        return None

    decoded = []
    idx = 1
    while idx < end:
        char = value[idx]
        if char == "$" and idx + 1 < end and value[idx + 1] == "{":
            return None
        if char != "\\":
            decoded.append(char)
            idx += 1
            continue

        idx += 1
        if idx >= end:
            return None
        escaped = value[idx]
        if escaped == "$" and idx + 1 < end and value[idx + 1] == "{":
            decoded.append("${")
            idx += 2
            continue
        decoded.append(_NIX_STRING_ESCAPES.get(escaped, f"\\{escaped}"))
        idx += 1
    return "".join(decoded)


def _find_quoted_attr_end(value: str) -> int | None:
    escaped = False
    for idx, char in enumerate(value[1:], start=1):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            return idx
    return None


def _looks_like_flakeref(flakeref: str) -> bool:
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
