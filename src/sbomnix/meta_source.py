# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Resolve nixpkgs metadata sources from target context."""

import json
import pathlib
import re
from dataclasses import dataclass, replace
from urllib.parse import urlencode

from common.flakeref import (
    NIXOS_CONFIGURATION_TOPLEVEL_SUFFIX,
    parse_nixos_configuration_ref,
    quote_nix_attr_segment,
)
from common.log import LOG
from common.proc import exec_cmd, nix_cmd
from sbomnix.flake_metadata import (
    nixref_to_nixpkgs_path,
    normalize_current_flake_shorthand,
    normalize_local_flake_ref,
)


@dataclass(frozen=True)
class NixpkgsMetaSource:
    """Description of the nixpkgs source used for metadata enrichment."""

    method: str
    path: str | None = None
    flakeref: str | None = None
    flakeref_cache_key: str | None = None
    rev: str | None = None
    version: str | None = None
    message: str | None = None
    expression: str | None = None
    expression_cache_key: str | None = None
    expression_impure: bool = False


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


def log_nixpkgs_meta_source(source):
    """Log a concise summary of a selected nixpkgs metadata source."""
    parts = [f"method '{source.method}'"]
    if source.path:
        parts.append(f"path '{source.path}'")
    if source.flakeref:
        parts.append(f"flakeref '{source.flakeref}'")
    LOG.verbose("Selected nixpkgs metadata source: %s", ", ".join(parts))


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
                "No nixpkgs metadata source is available for store-path targets. "
                "Skipping nixpkgs metadata. Use a flakeref target instead."
            ),
        )

    def resolve_flakeref_target_source(self, flakeref, *, impure=False):
        """Resolve target-specific nixpkgs metadata for known flakeref outputs."""
        flakeref = normalize_current_flake_shorthand(flakeref)
        parsed = self._parse_nixos_toplevel_flakeref(flakeref)
        if not parsed:
            return None
        LOG.info("Resolving nixpkgs path for '%s'", flakeref)
        flake, name = parsed
        name_attr = quote_nix_attr_segment(name)
        pkgs_path_ref = f"{flake}#nixosConfigurations.{name_attr}.pkgs.path"
        LOG.info("Evaluating nixpkgs path for '%s'", pkgs_path_ref)
        pkgs_path = self._nix_eval_raw(pkgs_path_ref, impure=impure)
        if pkgs_path:
            expression_flake = self._flake_ref_for_expression(
                flake,
                impure=impure,
            )
            flakeref_cache_key = self._stable_flakeref_cache_key(
                flakeref,
                impure=impure,
            )
            source = nixpkgs_meta_source_with_path(
                NixpkgsMetaSource(
                    method="flakeref-target",
                    path=pkgs_path,
                    flakeref=pkgs_path_ref,
                    flakeref_cache_key=flakeref_cache_key,
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
            log_nixpkgs_meta_source(source)
            return source

        return self._nixos_toplevel_without_source()

    @staticmethod
    def _nixos_toplevel_without_source():
        return NixpkgsMetaSource(
            method="none",
            message=(
                "Failed resolving target-specific nixpkgs metadata source from "
                "NixOS configuration flakeref. Skipping nixpkgs metadata."
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
        if self._should_lock_flake_ref(flake):
            locked_ref = self._locked_flake_ref_from_metadata(flake, impure=impure)
            if locked_ref:
                return locked_ref
        return normalize_local_flake_ref(flake)

    @staticmethod
    def _flake_ref_has_stable_lock(flake):
        return re.search(r"(?:[?&])(?:narHash|rev)=", flake) is not None

    @classmethod
    def _should_lock_flake_ref(cls, flake):
        if cls._flake_ref_has_stable_lock(flake):
            return False
        if cls._is_existing_local_flake_ref(flake):
            return True
        return bool(flake)

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

    @classmethod
    def _stable_flakeref_cache_key(cls, flakeref, *, impure=False):
        flakeref = normalize_current_flake_shorthand(flakeref)
        flake, separator, attr = str(flakeref or "").partition("#")
        if not flake:
            return None
        stable_flake = cls._stable_flake_ref_for_cache(flake)
        if not stable_flake and cls._should_lock_flake_ref(flake):
            stable_flake = cls._locked_flake_ref_from_metadata(flake, impure=impure)
        if not stable_flake:
            return None
        return f"{stable_flake}{separator}{attr}"

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

    @classmethod
    def _nixos_pkgs_expression_cache_key(cls, flake, name, *, impure=False):
        if impure:
            return None
        stable_ref = cls._stable_flake_ref_for_cache(flake)
        if not stable_ref:
            return None
        cache_parts = json.dumps([stable_ref, name], separators=(",", ":"))
        return f"nixos-pkgs:{cache_parts}"

    @staticmethod
    def _stable_flake_ref_for_cache(flake):
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

    def resolve_flakeref_lock_source(self, nixref, *, impure=False):
        """Return the nixpkgs source selected by a flakeref lock graph."""
        if nixref:
            nixref = normalize_current_flake_shorthand(nixref)
            nixpath = nixref_to_nixpkgs_path(nixref)
            flakeref_cache_key = self._stable_flakeref_cache_key(
                nixref,
                impure=impure,
            )
            if nixpath:
                source = nixpkgs_meta_source_with_path(
                    NixpkgsMetaSource(
                        method="flakeref-lock",
                        path=nixpath.as_posix(),
                        flakeref=nixref,
                        flakeref_cache_key=flakeref_cache_key,
                    ),
                )
                log_nixpkgs_meta_source(source)
                return source
        return NixpkgsMetaSource(method="none")
