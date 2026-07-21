#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared CLI orchestration helpers."""

import logging
import pathlib
import subprocess
from dataclasses import dataclass
from tempfile import NamedTemporaryFile

from common.errors import InvalidNixArtifactError, MissingNixOutPathError
from common.flakeref import (
    NIXOS_CONFIGURATION_TOPLEVEL_SUFFIX,
    parse_nixos_configuration_ref,
    quote_nix_attr_segment,
    try_resolve_flakeref,
)
from common.log import LOG
from common.proc import exec_cmd, exit_unless_nix_artifact, nix_cmd
from sbomnix.builder import SbomBuilder


@dataclass(frozen=True)
class ResolvedNixTarget:
    """Resolved nix CLI target."""

    path: str
    flakeref: str | None = None
    original_ref: str | None = None


@dataclass(frozen=True)
class GeneratedSbom:
    """Paths of generated temporary SBOM artifacts."""

    cdx_path: pathlib.Path
    csv_path: pathlib.Path | None = None

    def cleanup(self):
        """Remove generated artifacts if they exist."""
        self.cdx_path.unlink(missing_ok=True)
        if self.csv_path is not None:
            self.csv_path.unlink(missing_ok=True)


def resolve_nix_target(nixref, buildtime=False, impure=False):
    """Resolve a CLI target to a nix path, preserving flakeref context."""
    runtime = not buildtime
    resolved_ref = _normalize_nixos_configuration_ref(nixref)
    target_path = try_resolve_flakeref(
        resolved_ref,
        force_realise=runtime,
        impure=impure,
        derivation=buildtime,
    )
    if target_path:
        return ResolvedNixTarget(
            path=target_path,
            flakeref=resolved_ref,
            original_ref=nixref,
        )

    target_path = pathlib.Path(nixref).resolve().as_posix()
    if runtime and target_path.endswith(".drv"):
        target_path = _realise_derivation_output(target_path)
    else:
        exit_unless_nix_artifact(nixref, force_realise=runtime)
    return ResolvedNixTarget(path=target_path, original_ref=nixref)


def _realise_derivation_output(path):
    try:
        ret = exec_cmd(
            nix_cmd(
                "build",
                "--no-link",
                "--print-out-paths",
                f"{path}^*",
            )
        )
    except subprocess.CalledProcessError:
        raise InvalidNixArtifactError(path) from None
    out_path = next(
        (line.strip() for line in ret.stdout.splitlines() if line.strip()), ""
    )
    if not out_path:
        raise MissingNixOutPathError(path)
    LOG.debug("runtime derivation target '%s' maps to output '%s'", path, out_path)
    return out_path


def _normalize_nixos_configuration_ref(nixref):
    parsed = parse_nixos_configuration_ref(nixref)
    if not parsed:
        return nixref
    flake, name = parsed
    attr = quote_nix_attr_segment(name)
    return f"{flake}#nixosConfigurations.{attr}{NIXOS_CONFIGURATION_TOPLEVEL_SUFFIX}"


def _temp_sbom_path(prefix, suffix):
    with NamedTemporaryFile(delete=False, prefix=prefix, suffix=suffix) as fobj:
        return pathlib.Path(fobj.name)


def generate_temp_sbom(
    target_path,
    buildtime=False,
    prefix="sbomnix_",
    cdx_suffix=".cdx.json",
    include_csv=False,
):
    """Generate temporary SBOM artifact files for downstream CLI workflows."""
    LOG.info("Generating SBOM for target '%s'", target_path)
    sbom = SbomBuilder(target_path, buildtime, include_meta=False)
    cdx_path = None
    csv_path = None
    try:
        cdx_path = _temp_sbom_path(prefix, cdx_suffix)
        csv_path = _temp_sbom_path(prefix, ".csv") if include_csv else None
        sbom.to_cdx(cdx_path, printinfo=False)
        if csv_path is not None:
            sbom.to_csv(csv_path, loglevel=logging.DEBUG)
    except Exception:
        for path in (cdx_path, csv_path):
            if path is not None:
                path.unlink(missing_ok=True)
        raise
    return GeneratedSbom(cdx_path=cdx_path, csv_path=csv_path)
