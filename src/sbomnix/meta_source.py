# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Resolve nixpkgs metadata sources from target context."""

import json
import pathlib
import re
from dataclasses import dataclass
from subprocess import CalledProcessError
from urllib.parse import parse_qsl, urlencode, urlparse

from common.flakeref import (
    NIXOS_CONFIGURATION_TOPLEVEL_SUFFIX,
    parse_nixos_configuration_ref,
    quote_nix_attr_segment,
)
from common.log import LOG
from common.proc import exec_cmd, nix_cmd

SCAN_EXCEPTIONS = (KeyError, OSError, CalledProcessError, TypeError, ValueError)


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


@dataclass(frozen=True)
class NixpkgsMetaSource:
    """Description of the nixpkgs source used for metadata enrichment."""

    method: str
    path: str | None = None
    flakeref: str | None = None
    rev: str | None = None
    version: str | None = None
    message: str | None = None
    expression_cache_key: str | None = None
    expression_impure: bool = False
    pkgs_expression: str | None = None


class NixpkgsMetaSourceResolver:
    """Resolve a nixpkgs metadata source without scanning metadata."""

    _CACHE_MISS = object()

    def __init__(self):
        self._flake_metadata_cache = {}
        self._nix_eval_raw_cache = {}
        self._stable_ref_cache = {}
        self._expression_ref_cache = {}
        self._lock_source_cache = {}
        self._target_source_cache = {}

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

    def resolve_flakeref_lock_source(self, nixref, *, impure=False):
        """Return a flake-meta source for the given flakeref."""
        cache_key = (nixref, impure)
        cached = self._lock_source_cache.get(cache_key, self._CACHE_MISS)
        if cached is not self._CACHE_MISS:
            return cached
        if not nixref:
            source = NixpkgsMetaSource(method="none")
            self._lock_source_cache[cache_key] = source
            return source
        LOG.debug("Resolving flake-meta source for '%s'", nixref)
        flake_part, _, attr_part = nixref.partition("#")
        stable, meta_json = self._stable_flake_ref_with_metadata(
            flake_part,
            impure=impure,
        )
        pkgs_expression = None
        source_kwargs = {"flakeref": stable or nixref}
        if stable:
            # Probe whether the attr is a NixOS configuration name and use its
            # pkgs. NixOS configuration names are always bare identifiers, so
            # dotted attr paths (e.g. "haskellPackages.vector") are excluded
            # from the probe and fall through to the lock-graph path.
            if self._should_probe_nixos_pkgs_path(flake_part, attr_part, meta_json):
                quoted = quote_nix_attr_segment(attr_part)
                pkgs_path_ref = f"{stable}#nixosConfigurations.{quoted}.pkgs.path"
                pkgs_path = self._cached_nix_eval_raw(pkgs_path_ref, impure=impure)
                if pkgs_path:
                    pkgs_expression = self._nixos_pkgs_expression(stable, attr_part)
                    source_kwargs = {
                        "flakeref": pkgs_path_ref,
                        "path": pkgs_path,
                        "version": read_nixpkgs_version(pkgs_path),
                        "message": "Scanning evaluated NixOS package set from flakeref",
                    }
            # Try to resolve nixpkgs from the flake's lock graph. This handles
            # third-party flakes that pin nixpkgs as an input and preserves the
            # exact source details for SBOM export.
            if pkgs_expression is None:
                locked_source = self._locked_nixpkgs_source(
                    stable,
                    meta_json=meta_json,
                    impure=impure,
                )
                if locked_source is not None:
                    pkgs_expression = locked_source.pop("pkgs_expression")
                    source_kwargs = locked_source
            # Final fallback: import the flake directly. Works when the target
            # itself is nixpkgs; for other flakes the eval will fail and the scan
            # is skipped, matching pre-existing behaviour.
            if pkgs_expression is None:
                pkgs_expression = (
                    f"import (builtins.getFlake {json.dumps(stable)}) {{}}"
                )
                source_kwargs = self._source_details_from_flake_ref(stable)
        cache_key = f"flake-meta:{stable}#{attr_part}" if stable else None
        source = NixpkgsMetaSource(
            method="flake-meta",
            expression_cache_key=cache_key,
            expression_impure=impure,
            pkgs_expression=pkgs_expression,
            **source_kwargs,
        )
        self._lock_source_cache[(nixref, impure)] = source
        return source

    def _locked_nixpkgs_source(self, stable, *, meta_json=None, impure=False):
        """Return source details for the nixpkgs input in the lock graph.

        Returns a mapping containing pkgs_expression plus exportable source
        fields. Returns None when the flake itself is nixpkgs (caller uses
        import-flake directly), when the lock graph has no unambiguous nixpkgs
        input, or when the locked type is not supported.
        """
        if meta_json is None:
            meta_json = self._cached_nix_flake_metadata(stable, impure=impure)
        if meta_json is None:
            return None
        if self._is_nixpkgs_flake(meta_json):
            return None
        return self._nixpkgs_source_from_lock(meta_json)

    @staticmethod
    def _is_nixpkgs_flake(meta_json):
        """Return True if meta_json describes nixpkgs itself."""
        try:
            if (
                meta_json.get("description")
                == "A collection of packages for the Nix package manager"
            ):
                return True
            locked = meta_json.get("locked", {})
            return locked.get("owner") == "NixOS" and locked.get("repo") == "nixpkgs"
        except (AttributeError, TypeError):
            return False

    @staticmethod
    def _nixpkgs_source_from_lock(meta_json):
        """Build source details from the nixpkgs input in the flake lock graph.

        Prefers root.inputs.nixpkgs; falls back to a single unambiguous
        nixpkgs-like node.  Returns None when ambiguous or unsupported.
        """
        try:
            nodes = meta_json["locks"]["nodes"]
            root_name = meta_json["locks"]["root"]
            root_inputs = nodes[root_name].get("inputs", {})
        except (KeyError, TypeError, AttributeError):
            return None

        nixpkgs_input = root_inputs.get("nixpkgs")
        if isinstance(nixpkgs_input, str):
            node_names = [nixpkgs_input]
        elif (
            isinstance(nixpkgs_input, list)
            and nixpkgs_input
            and isinstance(nixpkgs_input[-1], str)
        ):
            # Lock-file override chains store the resolved input node as the
            # last element, e.g. root.inputs.nixpkgs = ["nixpkgs_3"].
            node_names = [nixpkgs_input[-1]]
        else:
            node_names = []

        if not node_names:
            candidates = []
            for node_name, node in nodes.items():
                try:
                    locked = node.get("locked") or {}
                    if NixpkgsMetaSourceResolver._locked_node_identifies_nixpkgs(
                        locked
                    ):
                        candidates.append(node_name)
                except (AttributeError, TypeError):
                    continue
            if len(candidates) == 1:
                node_names = candidates

        for node_name in node_names:
            try:
                locked = nodes[node_name]["locked"]
            except (KeyError, TypeError):
                continue
            source = NixpkgsMetaSourceResolver._nixpkgs_locked_source_details(locked)
            if source is not None:
                return source

        return None

    @staticmethod
    def _nixpkgs_locked_source_details(locked):
        """Convert a lock-graph locked object to source details."""
        try:
            lock_type = locked.get("type")
        except AttributeError:
            return None
        if lock_type == "github":
            return NixpkgsMetaSourceResolver._locked_github_source_details(locked)
        if lock_type == "git":
            return NixpkgsMetaSourceResolver._locked_git_source_details(locked)
        if lock_type == "tarball":
            return NixpkgsMetaSourceResolver._locked_tarball_source_details(locked)
        if lock_type == "path":
            return NixpkgsMetaSourceResolver._locked_path_source_details(locked)
        return None

    @staticmethod
    def _locked_node_identifies_nixpkgs(locked):
        """Return True when the locked object positively identifies nixpkgs.

        This fallback is intentionally narrower than the supported source-detail
        reconstructor: path inputs are only accepted when referenced explicitly
        through root.inputs.nixpkgs, not guessed by node name.
        """
        try:
            lock_type = locked.get("type")
        except AttributeError:
            return False
        if lock_type == "github":
            return locked.get("repo") == "nixpkgs"
        if lock_type in {"git", "tarball"}:
            return NixpkgsMetaSourceResolver._url_identifies_nixpkgs(locked.get("url"))
        return False

    @staticmethod
    def _url_identifies_nixpkgs(url):
        """Return True when a locked URL path clearly points at nixpkgs."""
        if not isinstance(url, str) or not url:
            return False
        try:
            path = urlparse(url).path
        except ValueError:
            return False
        segments = [
            segment.removesuffix(".git") for segment in path.split("/") if segment
        ]
        return "nixpkgs" in segments

    @staticmethod
    def _locked_dir(locked):
        try:
            locked_dir = locked.get("dir")
        except AttributeError:
            return None
        if isinstance(locked_dir, str) and locked_dir:
            return locked_dir
        return None

    @staticmethod
    def _append_query_params(ref, params):
        base, separator, query = ref.partition("?")
        query_pairs = (
            dict(parse_qsl(query, keep_blank_values=True)) if separator else {}
        )
        query_pairs.update(params)
        return f"{base}?{urlencode(query_pairs, safe='/')}"

    @staticmethod
    def _locked_query_parts(locked, **query_parts):
        nar_hash = locked.get("narHash")
        if nar_hash:
            query_parts["narHash"] = nar_hash
        locked_dir = NixpkgsMetaSourceResolver._locked_dir(locked)
        if locked_dir:
            query_parts["dir"] = locked_dir
        return query_parts

    @staticmethod
    def _locked_github_source_details(locked):
        owner = locked.get("owner")
        repo = locked.get("repo")
        rev = locked.get("rev")
        if not all([owner, repo, rev]):
            return None
        query_parts = NixpkgsMetaSourceResolver._locked_query_parts(locked, rev=rev)
        flakeref = f"github:{owner}/{repo}?{urlencode(query_parts, safe='/')}"
        return {
            "pkgs_expression": f"import (builtins.getFlake {json.dumps(flakeref)}) {{}}",
            "flakeref": flakeref,
            "rev": rev,
        }

    @staticmethod
    def _locked_git_source_details(locked):
        url = locked.get("url")
        rev = locked.get("rev")
        ref = locked.get("ref")
        # Keep ref in the emitted git+ flakeref so the locked source still
        # identifies the intended branch/tag context alongside the pinned rev.
        if not all([url, rev]):
            return None
        query_parts = {}
        if ref:
            query_parts["ref"] = ref
        query_parts["rev"] = rev
        query_parts = NixpkgsMetaSourceResolver._locked_query_parts(
            locked,
            **query_parts,
        )
        flakeref = f"git+{url}?{urlencode(query_parts, safe='/')}"
        return {
            "pkgs_expression": f"import (builtins.getFlake {json.dumps(flakeref)}) {{}}",
            "flakeref": flakeref,
            "rev": rev,
        }

    @staticmethod
    def _locked_tarball_source_details(locked):
        url = locked.get("url")
        if not url:
            return None
        flakeref = url
        query_parts = NixpkgsMetaSourceResolver._locked_query_parts(locked)
        if query_parts:
            flakeref = NixpkgsMetaSourceResolver._append_query_params(
                url,
                query_parts,
            )
        return {
            "pkgs_expression": f"import (builtins.getFlake {json.dumps(flakeref)}) {{}}",
            "flakeref": flakeref,
        }

    @staticmethod
    def _locked_path_source_details(locked):
        path = locked.get("path", "")
        if not path.startswith("/nix/store/"):
            return None
        locked_dir = NixpkgsMetaSourceResolver._locked_dir(locked)
        source_path = pathlib.PurePosixPath(path)
        if locked_dir:
            source_path /= locked_dir
        source_path_str = source_path.as_posix()
        flakeref = f"path:{path}"
        if locked_dir:
            flakeref = NixpkgsMetaSourceResolver._append_query_params(
                flakeref,
                {"dir": locked_dir},
            )
        return {
            "pkgs_expression": f"import {json.dumps(source_path_str)} {{}}",
            "flakeref": flakeref,
            "path": source_path_str,
            "version": read_nixpkgs_version(source_path_str),
        }

    def resolve_flakeref_target_source(self, flakeref, *, impure=False):
        """Resolve target-specific metadata for NixOS toplevel outputs."""
        cache_key = (flakeref, impure)
        cached = self._target_source_cache.get(cache_key)
        if cached is not None:
            return cached
        parsed = self._parse_nixos_toplevel_flakeref(flakeref)
        if not parsed:
            return None
        flake, name = parsed
        locked_flake = self._cached_flake_ref_for_expression(flake, impure=impure)
        if locked_flake is None:
            locked_flake = flake
        attr_part = flakeref.partition("#")[2]
        locked_ref = f"{locked_flake}#{attr_part}"
        pkgs_expression = None
        pkgs_path_ref = f"{locked_flake}#nixosConfigurations.{quote_nix_attr_segment(name)}.pkgs.path"
        pkgs_path = self._cached_nix_eval_raw(pkgs_path_ref, impure=impure)
        if pkgs_path:
            pkgs_expression = self._nixos_pkgs_expression(locked_flake, name)
        source = NixpkgsMetaSource(
            method="flake-meta",
            flakeref=pkgs_path_ref,
            path=pkgs_path,
            version=read_nixpkgs_version(pkgs_path) if pkgs_path else None,
            message=(
                "Scanning evaluated NixOS package set from flakeref"
                if pkgs_path
                else None
            ),
            expression_cache_key=self._flake_meta_cache_key(locked_ref, impure=impure),
            expression_impure=impure,
            pkgs_expression=pkgs_expression,
        )
        self._target_source_cache[(flakeref, impure)] = source
        return source

    @staticmethod
    def _nixos_pkgs_expression(flake, name):
        flake_json = json.dumps(flake)
        name_attr = quote_nix_attr_segment(name)
        return f"(builtins.getFlake {flake_json}).nixosConfigurations.{name_attr}.pkgs"

    @staticmethod
    def _nix_eval_raw(flakeref, *, impure=False):
        ret = exec_cmd(
            nix_cmd("eval", "--raw", flakeref, impure=impure),
            raise_on_error=False,
            return_error=True,
            log_error=False,
        )
        if ret is None or ret.returncode != 0:
            return None
        return ret.stdout.strip() or None

    def _cached_nix_eval_raw(self, flakeref, *, impure=False):
        key = (flakeref, impure)
        cached = self._nix_eval_raw_cache.get(key, self._CACHE_MISS)
        if cached is not self._CACHE_MISS:
            return cached
        value = self._nix_eval_raw(flakeref, impure=impure)
        self._nix_eval_raw_cache[key] = value
        return value

    @staticmethod
    def _source_details_from_flake_ref(flake_ref):
        """Return exportable source fields from a stable flake ref when possible."""
        flake_part = flake_ref.partition("#")[0]
        details = {"flakeref": flake_ref}
        rev = NixpkgsMetaSourceResolver._rev_from_flake_ref(flake_part)
        if rev:
            details["rev"] = rev
        path = NixpkgsMetaSourceResolver._store_path_from_flake_ref(flake_part)
        if path:
            details["path"] = path
            details["version"] = read_nixpkgs_version(path)
        return details

    @staticmethod
    def _rev_from_flake_ref(flake_ref):
        query = flake_ref.partition("?")[2]
        if not query:
            return None
        for key, value in parse_qsl(query, keep_blank_values=True):
            if key == "rev" and value:
                return value
        return None

    @staticmethod
    def _store_path_from_flake_ref(flake_ref):
        query = flake_ref.partition("?")[2]
        locked_dir = None
        if query:
            for key, value in parse_qsl(query, keep_blank_values=True):
                if key == "dir" and value:
                    locked_dir = value
                    break
        if flake_ref.startswith("path:/nix/store/"):
            source_path = pathlib.PurePosixPath(
                flake_ref.removeprefix("path:").partition("?")[0]
            )
            if locked_dir:
                source_path /= locked_dir
            return source_path.as_posix()
        if flake_ref.startswith("/nix/store/"):
            source_path = pathlib.PurePosixPath(flake_ref.partition("?")[0])
            if locked_dir:
                source_path /= locked_dir
            return source_path.as_posix()
        return None

    def _stable_flake_ref_with_metadata(self, flake_part, *, impure=False):
        """Return a stable ref plus the metadata used to derive it when available."""
        key = (flake_part, impure)
        cached = self._stable_ref_cache.get(key, self._CACHE_MISS)
        if cached is not self._CACHE_MISS:
            return cached
        if self._flake_ref_has_stable_lock(flake_part):
            value = (flake_part, None)
            self._stable_ref_cache[key] = value
            return value
        meta_json = self._cached_nix_flake_metadata(flake_part, impure=impure)
        value = (self._locked_flake_ref_from_meta_json(meta_json), meta_json)
        self._stable_ref_cache[key] = value
        return value

    @classmethod
    def _stable_flake_ref(cls, flake_part, *, impure=False):
        """Return a stable (locked) ref for flake_part, or None if not determinable."""
        if cls._flake_ref_has_stable_lock(flake_part):
            return flake_part
        return cls._locked_flake_ref_from_metadata(flake_part, impure=impure)

    @classmethod
    def _nixos_pkgs_from_attr(cls, stable, attr, *, impure=False):
        """Return a pkgs expression by probing nixosConfigurations.ATTR.pkgs.

        This handles targets like "ghaf#lenovo-x1-carbon-gen11-debug" where
        ATTR is a NixOS configuration name in the flake.  Returns None when
        the configuration or its pkgs attribute does not exist.
        """
        quoted = quote_nix_attr_segment(attr)
        pkgs_path_ref = f"{stable}#nixosConfigurations.{quoted}.pkgs.path"
        if cls._nix_eval_raw(pkgs_path_ref, impure=impure):
            return cls._nixos_pkgs_expression(stable, attr)
        return None

    @classmethod
    def _flake_meta_cache_key(cls, flake_str, *, impure=False):
        flake_part, _, attr_part = flake_str.partition("#")
        stable = cls._stable_flake_ref(flake_part, impure=impure)
        if stable is None:
            return None
        return f"flake-meta:{stable}#{attr_part}"

    @staticmethod
    def _parse_nixos_toplevel_flakeref(flakeref):
        return parse_nixos_configuration_ref(
            flakeref,
            suffix=NIXOS_CONFIGURATION_TOPLEVEL_SUFFIX,
        )

    def _cached_flake_ref_for_expression(self, flake, *, impure=False):
        key = (flake, impure)
        cached = self._expression_ref_cache.get(key, self._CACHE_MISS)
        if cached is not self._CACHE_MISS:
            return cached
        value = self._flake_ref_for_expression(flake, impure=impure)
        self._expression_ref_cache[key] = value
        return value

    def _flake_ref_for_expression(self, flake, *, impure=False):
        if self._flake_ref_has_stable_lock(flake):
            return flake
        if self._should_lock_flake_ref_for_expression(flake):
            locked_ref, _meta_json = self._stable_flake_ref_with_metadata(
                flake,
                impure=impure,
            )
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

    @classmethod
    def _should_probe_nixos_pkgs_path(cls, flake_part, attr_part, meta_json):
        """Return True when the attr likely denotes a shorthand NixOS config."""
        if not attr_part or "." in attr_part:
            return False
        if meta_json is not None and cls._is_nixpkgs_flake(meta_json):
            return False
        if cls._is_existing_local_flake_ref(flake_part):
            return True
        return any(ch in attr_part for ch in '-_:"')

    @staticmethod
    def _is_existing_local_flake_ref(flake):
        path_text = flake
        if flake.startswith("path:"):
            path_text = flake.removeprefix("path:").partition("?")[0]
        elif re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", flake or ""):
            return False
        return pathlib.Path(path_text).expanduser().exists()

    @staticmethod
    def _locked_flake_ref_from_meta_json(meta_json):
        try:
            source_path = meta_json["path"]
            locked = meta_json["locked"]
            nar_hash = locked["narHash"]
        except (KeyError, TypeError):
            return None
        if not source_path or not nar_hash or not source_path.startswith("/nix/store/"):
            return None
        query = {"narHash": nar_hash}
        locked_dir = locked.get("dir")
        if locked_dir:
            query["dir"] = locked_dir
        return f"path:{source_path}?{urlencode(query, safe='/')}"

    @staticmethod
    def _locked_flake_ref_from_metadata(flake, *, impure=False):
        meta_json = NixpkgsMetaSourceResolver._nix_flake_metadata(
            flake,
            impure=impure,
        )
        return NixpkgsMetaSourceResolver._locked_flake_ref_from_meta_json(meta_json)

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

    def _cached_nix_flake_metadata(self, flake, *, impure=False):
        key = (flake, impure)
        cached = self._flake_metadata_cache.get(key, self._CACHE_MISS)
        if cached is not self._CACHE_MISS:
            return cached
        value = self._nix_flake_metadata(flake, impure=impure)
        self._flake_metadata_cache[key] = value
        return value

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
