# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Flakeref resolution helpers."""

import logging
import pathlib
import re
import time
from dataclasses import dataclass

from common.errors import FlakeRefRealisationError, FlakeRefResolutionError
from common.log import LOG, LOG_VERBOSE
from common.nix_utils import (
    NIX_BUILD_JSON,
    load_nix_json,
    parse_nix_derivation_show,
)
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


@dataclass(frozen=True)
class RealisedFlakeRef:
    """A force-realised runtime flakeref target."""

    path: str
    drv_path: str | None = None


def try_resolve_flakeref(
    flakeref: str,
    impure: bool = False,
    derivation: bool = False,
    *,
    exec_cmd_fn: ExecCmdFn | None = None,
    log: logging.Logger | None = None,
) -> str | None:
    """
    Resolve flakeref to out-path, or to its derivation path if ``derivation``
    is True, without realising it.
    """
    exec_cmd_fn = exec_cmd if exec_cmd_fn is None else exec_cmd_fn
    log = LOG if log is None else log

    looks_like_flakeref = _looks_like_flakeref(flakeref)
    if derivation and looks_like_flakeref:
        return _resolve_flakeref_derivation(
            flakeref,
            impure=impure,
            exec_cmd_fn=exec_cmd_fn,
            log=log,
        )
    return _eval_flakeref_path(
        flakeref,
        looks_like_flakeref=looks_like_flakeref,
        impure=impure,
        exec_cmd_fn=exec_cmd_fn,
        log=log,
    )


def try_realise_flakeref(
    flakeref: str,
    impure: bool = False,
    *,
    exec_cmd_fn: ExecCmdFn | None = None,
    log: logging.Logger | None = None,
) -> RealisedFlakeRef | None:
    """
    Resolve and force-realise flakeref, returning its out-path and, when
    it has one, the derivation it was built from.
    """
    exec_cmd_fn = exec_cmd if exec_cmd_fn is None else exec_cmd_fn
    log = LOG if log is None else log

    if _looks_like_flakeref(flakeref):
        log.info("Evaluating flakeref '%s'", flakeref)
        return _build_flakeref(
            flakeref,
            impure=impure,
            exec_cmd_fn=exec_cmd_fn,
            log=log,
        )

    nixpath = _eval_flakeref_path(
        flakeref,
        looks_like_flakeref=False,
        impure=impure,
        exec_cmd_fn=exec_cmd_fn,
        log=log,
    )
    if nixpath is None:
        return None
    log.info("Realising flakeref '%s'", flakeref)
    cmd = nix_cmd("build", "--no-link", flakeref, impure=impure)
    started = time.perf_counter()
    ret = exec_cmd_fn(cmd, raise_on_error=False, return_error=True, log_error=False)
    elapsed = time.perf_counter() - started
    if ret is None or ret.returncode != 0:
        log.debug("nix build failed for '%s' after %.3fs", flakeref, elapsed)
        raise FlakeRefRealisationError(flakeref, ret.stderr if ret else "")
    log.log(LOG_VERBOSE, "Realised flakeref '%s' in %.3fs", flakeref, elapsed)
    return RealisedFlakeRef(nixpath)


def _eval_flakeref_path(flakeref, *, looks_like_flakeref, impure, exec_cmd_fn, log):
    """Return the out-path ``nix eval`` resolves flakeref to."""
    if looks_like_flakeref:
        log.info("Evaluating flakeref '%s'", flakeref)
    else:
        log.log(LOG_VERBOSE, "Evaluating '%s'", flakeref)
    cmd = nix_cmd("eval", "--raw", flakeref, impure=impure)
    started = time.perf_counter()
    ret = exec_cmd_fn(cmd, raise_on_error=False, return_error=True, log_error=False)
    elapsed = time.perf_counter() - started
    if ret is None or ret.returncode != 0:
        log.debug("nix eval failed for '%s' after %.3fs", flakeref, elapsed)
        if looks_like_flakeref:
            raise FlakeRefResolutionError(flakeref, ret.stderr if ret else "")
        log.debug("not a flakeref: '%s'", flakeref)
        return None
    nixpath = ret.stdout.strip()
    log.log(LOG_VERBOSE, "Evaluated '%s' in %.3fs", flakeref, elapsed)
    log.debug("flakeref='%s' maps to path='%s'", flakeref, nixpath)
    return nixpath


def _first_built_target(stdout: str) -> RealisedFlakeRef | None:
    """Return the first target from ``nix build --json``."""
    built = load_nix_json(stdout, NIX_BUILD_JSON)
    if not isinstance(built, list) or not built:
        return None
    return _built_target(built[0])


def _built_target(entry) -> RealisedFlakeRef | None:
    """Return one ``nix build --json`` entry as a realised target.

    A derivation is ``{"drvPath": ..., "outputs": {name: path}}``.
    A plain store path is a bare string.
    """
    if isinstance(entry, str):
        return RealisedFlakeRef(entry) if entry else None
    if not isinstance(entry, dict):
        return None
    outputs = entry.get("outputs")
    drv_path = entry.get("drvPath")
    if not isinstance(outputs, dict) or not isinstance(drv_path, str):
        return None
    paths = [path for _name, path in sorted(outputs.items()) if isinstance(path, str)]
    return RealisedFlakeRef(paths[0], drv_path) if paths else None


def _resolve_flakeref_derivation(flakeref, *, impure, exec_cmd_fn, log):
    """Return the derivation path for a flakeref target."""
    log.info("Evaluating flakeref '%s'", flakeref)
    cmd = nix_cmd("derivation", "show", flakeref, impure=impure)
    started = time.perf_counter()
    ret = exec_cmd_fn(cmd, raise_on_error=False, return_error=True, log_error=False)
    elapsed = time.perf_counter() - started
    if ret is None or ret.returncode != 0:
        log.debug(
            "nix derivation show failed for flakeref '%s' after %.3fs",
            flakeref,
            elapsed,
        )
        raise FlakeRefResolutionError(flakeref, ret.stderr if ret else "")
    drv_paths = parse_nix_derivation_show(ret.stdout)
    drv_path = next(iter(drv_paths), "")
    if not drv_path:
        raise FlakeRefResolutionError(
            flakeref,
            "nix derivation show returned no derivation path",
        )
    log.log(
        LOG_VERBOSE,
        "Resolved flakeref derivation in %.3fs to '%s'",
        elapsed,
        drv_path,
    )
    log.debug("flakeref='%s' maps to derivation='%s'", flakeref, drv_path)
    return drv_path


def _build_flakeref(flakeref, *, impure, exec_cmd_fn, log):
    """Build a flakeref target and return the first output and derivation."""
    log.info("Realising flakeref '%s'", flakeref)
    cmd = nix_cmd(
        "build",
        "--no-link",
        "--json",
        flakeref,
        impure=impure,
    )
    started = time.perf_counter()
    ret = exec_cmd_fn(cmd, raise_on_error=False, return_error=True, log_error=False)
    elapsed = time.perf_counter() - started
    if ret is None or ret.returncode != 0:
        log.debug("nix build failed for flakeref '%s' after %.3fs", flakeref, elapsed)
        raise FlakeRefRealisationError(flakeref, ret.stderr if ret else "")
    target = _first_built_target(ret.stdout)
    if target is None:
        raise FlakeRefRealisationError(
            flakeref,
            "nix build returned no output path",
        )
    log.log(
        LOG_VERBOSE,
        "Resolved flakeref to built path '%s' in %.3fs",
        target.path,
        elapsed,
    )
    log.debug(
        "flakeref='%s' maps to path='%s', derivation='%s'",
        flakeref,
        target.path,
        target.drv_path,
    )
    return target


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
