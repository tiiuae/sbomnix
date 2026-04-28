#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared CLI orchestration helpers."""

import logging
import pathlib
from dataclasses import dataclass
from tempfile import NamedTemporaryFile

from common.flakeref import (
    NIXOS_CONFIGURATION_TOPLEVEL_SUFFIX,
    parse_nixos_configuration_ref,
    quote_nix_attr_segment,
    try_resolve_flakeref,
)
from common.log import LOG
from common.proc import exit_unless_nix_artifact
from sbomnix.sbomdb import SbomDb


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
    exit_unless_nix_artifact(nixref, force_realise=runtime)
    return ResolvedNixTarget(path=target_path, original_ref=nixref)


def _normalize_nixos_configuration_ref(nixref):
    parsed = parse_nixos_configuration_ref(nixref)
    if not parsed:
        return nixref
    flake, name = parsed
    attr = quote_nix_attr_segment(name)
    return f"{flake}#nixosConfigurations.{attr}{NIXOS_CONFIGURATION_TOPLEVEL_SUFFIX}"


def generate_temp_sbom(
    target_path,
    buildtime=False,
    prefix="sbomnix_",
    cdx_suffix=".cdx.json",
    include_csv=False,
):
    """Generate temporary SBOM artifact files for downstream CLI workflows."""
    LOG.info("Generating SBOM for target '%s'", target_path)
    sbomdb = SbomDb(target_path, buildtime, include_meta=False)
    cdx_path = None
    csv_path = None
    try:
        with NamedTemporaryFile(delete=False, prefix=prefix, suffix=cdx_suffix) as fcdx:
            cdx_path = pathlib.Path(fcdx.name)
            if not include_csv:
                sbomdb.to_cdx(cdx_path, printinfo=False)
                return GeneratedSbom(cdx_path=cdx_path)
            with NamedTemporaryFile(delete=False, prefix=prefix, suffix=".csv") as fcsv:
                csv_path = pathlib.Path(fcsv.name)
                sbomdb.to_cdx(cdx_path, printinfo=False)
                sbomdb.to_csv(csv_path, loglevel=logging.DEBUG)
        return GeneratedSbom(cdx_path=cdx_path, csv_path=csv_path)
    except Exception:
        if cdx_path is not None:
            cdx_path.unlink(missing_ok=True)
        if csv_path is not None:
            csv_path.unlink(missing_ok=True)
        raise
