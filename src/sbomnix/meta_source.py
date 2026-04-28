# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Resolve nixpkgs metadata sources from target context and CLI options."""

import json
import os
import pathlib
import re
from dataclasses import dataclass, replace
from subprocess import CalledProcessError
from urllib.parse import urlencode

from common.errors import SbomnixError
from common.flakeref import (
    NIXOS_CONFIGURATION_TOPLEVEL_SUFFIX,
    parse_nixos_configuration_ref,
    quote_nix_attr_segment,
)
from common.log import LOG
from common.proc import exec_cmd, nix_cmd
from nixmeta.scanner import nixref_to_nixpkgs_path

META_NIXPKGS_NIX_PATH = "nix-path"

RESERVED_META_NIXPKGS_MODES = frozenset({META_NIXPKGS_NIX_PATH})

SCAN_EXCEPTIONS = (KeyError, OSError, CalledProcessError, TypeError, ValueError)
_NIXREF_RESOLUTION_EXCEPTIONS = (AttributeError, *SCAN_EXCEPTIONS)


@dataclass(frozen=True)
class NixpkgsMetaSource:
    """Description of the nixpkgs source used for metadata enrichment."""

    method: str
    path: str | None = None
    flakeref: str | None = None
    rev: str | None = None
    version: str | None = None
    message: str | None = None
    expression: str | None = None
    expression_cache_key: str | None = None
    expression_impure: bool = False


def classify_meta_nixpkgs(value):
    """Classify a --meta-nixpkgs value as a reserved mode or explicit source."""
    if value in RESERVED_META_NIXPKGS_MODES:
        return value
    return "explicit"


def read_nixpkgs_version(nixpkgs_path):
    """Read nixpkgs version from a source path if available."""
    try:
        return (
            (pathlib.Path(nixpkgs_path) / "lib" / ".version")
            .read_text(encoding="utf-8")
            .strip()
        )
    except OSError:
        return None


def is_nix_store_path(path):
    """Return true when path syntactically points into /nix/store."""
    return pathlib.Path(path).as_posix().startswith("/nix/store/")


def nixpkgs_meta_source_with_path(source):
    """Attach path-local nixpkgs version to a metadata source."""
    if not source.path:
        return source
    return replace(source, version=read_nixpkgs_version(source.path))


class NixpkgsMetaSourceResolver:
    """Resolve a nixpkgs metadata source without scanning metadata."""

    @staticmethod
    def path_target_without_source(target_path=None, original_ref=None):
        """Return the no-source result for store-path targets."""
        LOG.debug(
            "No automatic nixpkgs metadata source for target path=%s original_ref=%s",
            target_path,
            original_ref,
        )
        return NixpkgsMetaSource(
            method="none",
            message=(
                "No nixpkgs metadata source was provided for store-path target. "
                "Skipping nixpkgs metadata. Re-run with "
                "--meta-nixpkgs <nixpkgs-flakeref-or-path> to include metadata."
            ),
        )

    def resolve_meta_nixpkgs_option(self, meta_nixpkgs, *, target_path=None):
        """Resolve an explicit --meta-nixpkgs source or reserved mode."""
        LOG.debug(
            "Resolving explicit nixpkgs metadata source for target path=%s",
            target_path,
        )
        mode = classify_meta_nixpkgs(meta_nixpkgs)
        if mode == META_NIXPKGS_NIX_PATH:
            return self.resolve_nix_path_source(
                message="NIX_PATH metadata source may not match the target",
                required=True,
            )
        return self.resolve_explicit_source(meta_nixpkgs)

    def resolve_flakeref_target_source(self, flakeref, *, impure=False):
        """Resolve target-specific nixpkgs metadata for known flakeref outputs."""
        parsed = self._parse_nixos_toplevel_flakeref(flakeref)
        if not parsed:
            return None
        flake, name = parsed
        name_attr = quote_nix_attr_segment(name)
        pkgs_path_ref = f"{flake}#nixosConfigurations.{name_attr}.pkgs.path"
        pkgs_path = self._nix_eval_raw(pkgs_path_ref, impure=impure)
        if pkgs_path:
            expression_flake = self._flake_ref_for_expression(
                flake,
                impure=impure,
            )
            return nixpkgs_meta_source_with_path(
                NixpkgsMetaSource(
                    method="flakeref-target",
                    path=pkgs_path,
                    flakeref=pkgs_path_ref,
                    message="Scanning evaluated NixOS package set from flakeref",
                    expression=self._nixos_pkgs_expression(expression_flake, name),
                    expression_cache_key=self._nixos_pkgs_expression_cache_key(
                        expression_flake,
                        name,
                        impure=impure,
                    ),
                    expression_impure=impure,
                ),
            )

        revision_ref = (
            f"{flake}#nixosConfigurations.{name_attr}.config.system.nixos.revision"
        )
        rev = self._nix_eval_raw(revision_ref, impure=impure)
        if not rev:
            return self._nixos_toplevel_without_source()
        nixpkgs_flakeref = f"github:NixOS/nixpkgs?rev={rev}"
        nixpath = nixref_to_nixpkgs_path(nixpkgs_flakeref)
        if not nixpath:
            return self._nixos_toplevel_without_source()
        return nixpkgs_meta_source_with_path(
            NixpkgsMetaSource(
                method="flakeref-target",
                path=nixpath.as_posix(),
                flakeref=nixpkgs_flakeref,
                rev=rev,
                message=(
                    "Resolved nixpkgs from NixOS configuration revision as a "
                    "best-effort fallback; this may not represent forked, patched, "
                    "dirty, local, or offline nixpkgs inputs"
                ),
            ),
        )

    @staticmethod
    def _nixos_toplevel_without_source():
        return NixpkgsMetaSource(
            method="none",
            message=(
                "Failed resolving target-specific nixpkgs metadata source from "
                "NixOS configuration flakeref. Skipping nixpkgs metadata. Re-run "
                "with --meta-nixpkgs <nixpkgs-flakeref-or-path> to include metadata."
            ),
        )

    @staticmethod
    def _parse_nixos_toplevel_flakeref(flakeref):
        return parse_nixos_configuration_ref(
            flakeref,
            suffix=NIXOS_CONFIGURATION_TOPLEVEL_SUFFIX,
        )

    @staticmethod
    def _nixos_pkgs_expression(flake, name):
        flake_json = json.dumps(flake)
        name_attr = quote_nix_attr_segment(name)
        return (
            "let\n"
            f"  flake = builtins.getFlake {flake_json};\n"
            "in\n"
            f"  flake.nixosConfigurations.{name_attr}.pkgs\n"
        )

    def _flake_ref_for_expression(self, flake, *, impure=False):
        if self._flake_ref_has_stable_lock(flake):
            return flake
        if self._should_lock_flake_ref_for_expression(flake):
            locked_ref = self._locked_flake_ref_from_metadata(flake, impure=impure)
            if locked_ref:
                return locked_ref
        return self._normalize_local_flake_ref_for_expression(flake)

    @staticmethod
    def _flake_ref_has_stable_lock(flake):
        return re.search(r"(?:[?&])(?:narHash|rev)=", flake) is not None

    @classmethod
    def _should_lock_flake_ref_for_expression(cls, flake):
        if cls._flake_ref_has_stable_lock(flake):
            return False
        if cls._is_existing_local_flake_ref(flake):
            return True
        return re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", flake or "") is not None

    @staticmethod
    def _is_existing_local_flake_ref(flake):
        path_text = flake
        if flake.startswith("path:"):
            path_text = flake.removeprefix("path:").partition("?")[0]
        elif re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", flake or ""):
            return False
        return pathlib.Path(path_text).expanduser().exists()

    @staticmethod
    def _locked_flake_ref_from_metadata(flake, *, impure=False):
        meta_json = NixpkgsMetaSourceResolver._nix_flake_metadata(
            flake,
            impure=impure,
        )
        if meta_json is None:
            return None
        try:
            source_path = meta_json["path"]
            locked = meta_json["locked"]
            nar_hash = locked["narHash"]
        except (KeyError, TypeError):
            return None
        if not source_path or not nar_hash or not is_nix_store_path(source_path):
            return None
        query = {"narHash": nar_hash}
        locked_dir = locked.get("dir")
        if locked_dir:
            query["dir"] = locked_dir
        return f"path:{source_path}?{urlencode(query, safe='/')}"

    @staticmethod
    def _nix_flake_metadata(flake, *, impure=False):
        LOG.debug("Reading flake metadata for nixpkgs metadata expression: %s", flake)
        ret = exec_cmd(
            nix_cmd("flake", "metadata", flake, "--json", impure=impure),
            raise_on_error=False,
            return_error=True,
            log_error=False,
        )
        if ret is None or ret.returncode != 0:
            LOG.debug("Failed reading flake metadata for expression: %s", flake)
            return None
        try:
            return json.loads(ret.stdout)
        except ValueError:
            LOG.debug("Failed parsing flake metadata for expression: %s", flake)
            return None

    @staticmethod
    def _normalize_local_flake_ref_for_expression(flake):
        if flake.startswith("path:"):
            path_text, separator, query = flake.removeprefix("path:").partition("?")
            path = pathlib.Path(path_text).expanduser()
            if not path.is_absolute():
                path_text = path.resolve().as_posix()
            return f"path:{path_text}{separator}{query}"
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", flake or ""):
            return flake
        path = pathlib.Path(flake).expanduser()
        if path.exists() or flake.startswith((".", "/", "~")):
            return path.resolve().as_posix()
        return flake

    @classmethod
    def _nixos_pkgs_expression_cache_key(cls, flake, name, *, impure=False):
        if impure:
            return None
        stable_ref = cls._stable_flake_ref_for_expression_cache(flake)
        if not stable_ref:
            return None
        cache_parts = json.dumps([stable_ref, name], separators=(",", ":"))
        return f"nixos-pkgs:{cache_parts}"

    @staticmethod
    def _stable_flake_ref_for_expression_cache(flake):
        if flake.startswith("path:/nix/store/"):
            return flake
        if flake.startswith("/nix/store/"):
            return flake
        if re.search(r"(?:[?&])rev=", flake):
            return flake
        return None

    @staticmethod
    def _nix_eval_raw(flakeref, *, impure=False):
        LOG.debug("Evaluating nixpkgs metadata helper flakeref '%s'", flakeref)
        ret = exec_cmd(
            nix_cmd("eval", "--raw", flakeref, impure=impure),
            raise_on_error=False,
            return_error=True,
            log_error=False,
        )
        if ret is None or ret.returncode != 0:
            LOG.debug(
                "Failed evaluating nixpkgs metadata helper flakeref: %s", flakeref
            )
            return None
        return ret.stdout.strip() or None

    def resolve_explicit_source(self, meta_nixpkgs):
        """Resolve an explicit --meta-nixpkgs path or flakeref."""
        path = pathlib.Path(meta_nixpkgs)
        if path.exists():
            resolved_path = path.resolve()
            if is_nix_store_path(resolved_path):
                return nixpkgs_meta_source_with_path(
                    NixpkgsMetaSource(
                        method="explicit",
                        path=resolved_path.as_posix(),
                    ),
                )
            nixpath = self._try_normalize_mutable_path(resolved_path)
            if nixpath:
                return nixpkgs_meta_source_with_path(
                    NixpkgsMetaSource(
                        method="explicit",
                        path=nixpath.as_posix(),
                        flakeref=resolved_path.as_posix(),
                    ),
                )
            raise SbomnixError(
                "Explicit --meta-nixpkgs path must resolve to an immutable "
                f"/nix/store source before scanning: '{meta_nixpkgs}'"
            )
        try:
            nixpath = nixref_to_nixpkgs_path(meta_nixpkgs)
        except _NIXREF_RESOLUTION_EXCEPTIONS as error:
            raise SbomnixError(
                f"Failed resolving --meta-nixpkgs source: '{meta_nixpkgs}'"
            ) from error
        if not nixpath:
            raise SbomnixError(
                f"Failed resolving --meta-nixpkgs source: '{meta_nixpkgs}'"
            )
        return nixpkgs_meta_source_with_path(
            NixpkgsMetaSource(
                method="explicit",
                path=nixpath.as_posix(),
                flakeref=meta_nixpkgs,
            ),
        )

    @staticmethod
    def _try_normalize_mutable_path(path):
        try:
            nixpath = nixref_to_nixpkgs_path(path.as_posix())
        except _NIXREF_RESOLUTION_EXCEPTIONS:
            LOG.debug(
                "Failed normalizing mutable nixpkgs path: %s",
                path.as_posix(),
                exc_info=True,
            )
            return None
        if nixpath and is_nix_store_path(nixpath):
            return nixpath
        return None

    def resolve_legacy_source(self, nixref=None):
        """Return the metadata source selected by the legacy lookup policy."""
        if nixref:
            LOG.debug("Reading nixpkgs path from nixref: %s", nixref)
            nixpath = nixref_to_nixpkgs_path(nixref)
            if nixpath:
                return nixpkgs_meta_source_with_path(
                    NixpkgsMetaSource(
                        method="flakeref-lock",
                        path=nixpath.as_posix(),
                        flakeref=nixref,
                    ),
                )
        elif "NIX_PATH" in os.environ:
            return self.resolve_nix_path_source()
        return NixpkgsMetaSource(method="none")

    def resolve_nix_path_source(self, *, message=None, required=False):
        """Return the nixpkgs source referenced by NIX_PATH."""
        LOG.debug("Reading nixpkgs path from NIX_PATH environment")
        nix_path = os.environ.get("NIX_PATH", "")
        m_nixpkgs = re.search(r"(?:^|:)nixpkgs=([^:]+)", nix_path)
        if m_nixpkgs:
            return nixpkgs_meta_source_with_path(
                NixpkgsMetaSource(
                    method="nix-path",
                    path=m_nixpkgs.group(1),
                    message=message,
                ),
            )
        if required:
            raise SbomnixError(
                "NIX_PATH does not contain a nixpkgs= entry required by "
                "--meta-nixpkgs nix-path"
            )
        return NixpkgsMetaSource(method="none")
