# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Cache and scan nixpkgs meta information."""

import functools
import hashlib
import pathlib
from dataclasses import replace

from filelock import FileLock

from common.log import LOG
from nixmeta import metadata_json
from nixmeta import scanner as nixmeta_scanner
from nixmeta.resources import meta_nix_path
from nixmeta.scanner import NixMetaScanner
from sbomnix.artifacts import is_non_package_artifact_name
from sbomnix.cache_paths import meta_lock_path
from sbomnix.dfcache import LockedDfCache
from sbomnix.meta_source import (
    SCAN_EXCEPTIONS,
    NixpkgsMetaSource,
    NixpkgsMetaSourceResolver,
)

###############################################################################

# Update locally generated nixpkgs meta-info every 30 days or when local cache
# is cleaned.
_NIXMETA_NIXPKGS_TTL = 60 * 60 * 24 * 30
_META_CACHE_SCHEMA = "v2"

__all__ = [
    "Meta",
    "NixpkgsMetaSource",
]


def _names_hash(names):
    """Return a short stable hex digest of a sorted name list for cache-key disambiguation."""
    h = hashlib.sha256()
    for n in sorted(names):
        h.update(n.encode())
        h.update(b"\0")
    return h.hexdigest()[:16]


@functools.cache
def _meta_cache_fingerprint():
    """Return a short hash for the metadata lookup implementation."""
    try:
        paths = [
            meta_nix_path(),
            pathlib.Path(metadata_json.__file__),
            pathlib.Path(nixmeta_scanner.__file__),
        ]
        h = hashlib.sha256()
        h.update(_META_CACHE_SCHEMA.encode())
        h.update(b"\0")
        for path in paths:
            h.update(path.read_bytes())
            h.update(b"\0")
        return h.hexdigest()[:16]
    except OSError as error:
        LOG.warning("Packaged nixmeta helper is unavailable: %s", error)
        return "missing"


def _with_buildtime_suffix(source, buildtime):
    """Append a buildtime/runtime suffix to the cache key to avoid collisions."""
    if source.expression_cache_key is None:
        return source
    suffix = ":bt" if buildtime else ":rt"
    return replace(source, expression_cache_key=source.expression_cache_key + suffix)


def _filter_store_names_for_meta_scan(names):
    """Drop non-package artifact names before exact nixpkgs metadata lookup."""
    filtered = [name for name in names if not is_non_package_artifact_name(name)]
    skipped = len(names) - len(filtered)
    if skipped:
        LOG.debug(
            "Skipping nixpkgs metadata lookup for %d non-package artifact name(s)",
            skipped,
        )
    return filtered


class Meta:
    """Cache nixpkgs meta information."""

    def __init__(self):
        self.lock = FileLock(meta_lock_path())
        self.cache = LockedDfCache()
        self.source_resolver = NixpkgsMetaSourceResolver()
        self._last_scan_complete = True

    def get_nixpkgs_meta_with_source(  # noqa: PLR0913
        self,
        *,
        target_path=None,
        flakeref=None,
        original_ref=None,
        impure=False,
        store_names=None,
        buildtime=False,
    ):
        """Return nixpkgs metadata and selected metadata source."""
        source = self._resolve_source(
            target_path=target_path,
            flakeref=flakeref,
            original_ref=original_ref,
            impure=impure,
            buildtime=buildtime,
        )
        return self._scan_source_with_source(source, store_names=store_names)

    def _resolve_source(
        self,
        *,
        target_path=None,
        flakeref=None,
        original_ref=None,
        impure=False,
        buildtime=False,
    ):
        if flakeref:
            source = self.source_resolver.resolve_flakeref_target_source(
                flakeref,
                impure=impure,
            )
            if source is not None:
                return _with_buildtime_suffix(source, buildtime)
            source = self.source_resolver.resolve_flakeref_lock_source(
                flakeref, impure=impure
            )
            return _with_buildtime_suffix(source, buildtime)
        return self.source_resolver.path_target_without_source(
            target_path=target_path,
            original_ref=original_ref,
        )

    def _scan_source_with_source(self, source, *, store_names=None):
        if source.method != "flake-meta":
            return None, source

        message = None
        if store_names is None:
            message = "No store-path names supplied. Skipping nixpkgs metadata."
        else:
            store_names = _filter_store_names_for_meta_scan(store_names)
            if not store_names:
                message = (
                    "No scannable store-path names supplied. Skipping nixpkgs metadata."
                )
            elif source.pkgs_expression is None:
                message = (
                    "No nixpkgs expression resolved for this target. "
                    "Skipping nixpkgs metadata."
                )
        if message is not None:
            return None, replace(source, message=message)

        df = self._scan_store_names(
            store_names,
            cache_key=source.expression_cache_key,
            impure=source.expression_impure,
            pkgs_expr=source.pkgs_expression,
        )
        out_source = source
        if df is not None and not df.empty:
            if self._last_scan_complete:
                return df, source
            warning = (
                "meta.nix scan partially failed. Some packages are missing "
                "nixpkgs metadata."
            )
            LOG.warning("%s", warning)
            out_source = replace(source, message=warning)
            return df, out_source

        if df is None:
            message = "meta.nix scan failed. Skipping nixpkgs metadata."
        elif not self._last_scan_complete:
            message = (
                "meta.nix scan partially failed. No packages matched in the "
                "successful batches."
            )
        else:
            message = (
                "No packages matched in nixpkgs metadata scan. "
                "Skipping nixpkgs metadata."
            )
        out_source = replace(source, message=message)
        return None, out_source

    def _scan_store_names(self, names, *, cache_key=None, impure=False, pkgs_expr=None):
        if impure or cache_key is None:
            with self.lock:
                LOG.debug("cache disabled for store-names scan (%d names)", len(names))
                df, is_complete = self._try_scan_store_names(
                    names, impure=impure, pkgs_expr=pkgs_expr
                )
                self._last_scan_complete = is_complete
                return df
        key = (
            f"expr:{cache_key}:meta_fingerprint:{_meta_cache_fingerprint()}:"
            f"names:{_names_hash(names)}"
        )
        with self.lock:
            df = self.cache.get(key)
            if df is not None and not df.empty:
                LOG.debug("found from cache: %s", key)
                self._last_scan_complete = True
                return df
            LOG.debug("cache miss, scanning store names: %s", key)
            df, is_complete = self._try_scan_store_names(
                names, impure=impure, pkgs_expr=pkgs_expr
            )
            self._last_scan_complete = is_complete
            if df is not None and not df.empty:
                if is_complete:
                    self.cache.set(key=key, value=df, ttl=_NIXMETA_NIXPKGS_TTL)
                else:
                    LOG.warning(
                        "Skipping metadata cache for %s: some batches failed; "
                        "result will be re-scanned on the next run",
                        key,
                    )
            return df

    @staticmethod
    def _try_scan_store_names(names, *, impure=False, pkgs_expr=None):
        """Scan store names; returns (df, is_complete) where is_complete is False
        if any batch eval failed."""
        try:
            scanner = NixMetaScanner()
            scanner.scan_store_names(names, impure=impure, pkgs_expr=pkgs_expr)
            return scanner.to_df(), not scanner.had_failures
        except SCAN_EXCEPTIONS:
            LOG.debug("Failed scanning store names", exc_info=True)
            return None, False


###############################################################################
