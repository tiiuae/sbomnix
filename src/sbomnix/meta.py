# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Cache and scan nixpkgs meta information."""

import functools
import time
from dataclasses import replace

from filelock import FileLock

from common import columns as cols
from common.log import LOG
from sbomnix.cache_paths import meta_lock_path
from sbomnix.dfcache import LockedDfCache
from sbomnix.meta_source import (
    NixpkgsMetaSource,
    NixpkgsMetaSourceResolver,
)
from sbomnix.package_meta import (
    PACKAGE_META_METHOD,
    match_package_metadata_to_components,
    package_meta_cache_fingerprint,
    package_meta_candidate_key,
    package_meta_lookup_keys_for_components,
    try_scan_package_meta,
)

###############################################################################

# Update generated package metadata every 30 days or when local cache is cleaned.
_PACKAGE_META_TTL = 60 * 60 * 24 * 30

__all__ = [
    "Meta",
    "NixpkgsMetaSource",
]


class Meta:
    """Cache nixpkgs meta information."""

    def __init__(self):
        self.lock = FileLock(str(meta_lock_path()))
        self.cache = LockedDfCache()
        self.source_resolver = NixpkgsMetaSourceResolver()

    def get_package_meta_with_source(  # noqa: PLR0913
        self,
        *,
        components,
        buildtime,
        target_path=None,
        flakeref=None,
        original_ref=None,
        impure=False,
    ):
        """Return exact component metadata and selected metadata source."""
        started = time.perf_counter()
        source = self._resolve_source(
            target_path=target_path,
            flakeref=flakeref,
            original_ref=original_ref,
            impure=impure,
        )
        LOG.verbose(
            "Resolved nixpkgs metadata source method '%s' in %.3fs",
            source.method,
            time.perf_counter() - started,
        )
        component_count = 0 if components is None else len(components)
        LOG.verbose("Resolving package metadata for %d component(s)", component_count)
        out_source = replace(
            source,
            method=f"{source.method}+{PACKAGE_META_METHOD}",
        )
        if not source.path and not source.expression and not flakeref:
            return None, source
        lookup_keys = package_meta_lookup_keys_for_components(components)
        if not lookup_keys:
            return None, replace(
                out_source,
                message="No scannable package names supplied. Skipping nixpkgs metadata.",
            )
        LOG.verbose(
            "Looking up nixpkgs metadata for %d package name(s)", len(lookup_keys)
        )
        df_candidates = self._scan_package_source(
            source,
            lookup_keys,
            flakeref=_package_scan_flakeref(source, flakeref),
            walk_target=not _has_nixos_system(components),
            impure=impure,
        )
        if df_candidates is None:
            return None, replace(
                out_source,
                message="package_meta.nix scan failed. Skipping nixpkgs metadata.",
            )
        df = match_package_metadata_to_components(
            components,
            df_candidates,
            buildtime=buildtime,
        )
        if df.empty:
            return None, replace(
                out_source,
                message=(
                    "No package metadata matched component derivation "
                    "or output paths. Skipping nixpkgs metadata."
                ),
            )
        LOG.verbose(
            "Matched nixpkgs metadata for %d component(s) in %.3fs",
            len(df),
            time.perf_counter() - started,
        )
        return df, out_source

    def _resolve_source(
        self,
        *,
        target_path=None,
        flakeref=None,
        original_ref=None,
        impure=False,
    ):
        if flakeref:
            source = self.source_resolver.resolve_flakeref_target_source(
                flakeref,
                impure=impure,
            )
            if source is not None:
                return source
            return self.source_resolver.resolve_flakeref_lock_source(
                flakeref,
                impure=impure,
            )

        return self.source_resolver.path_target_without_source(
            target_path=target_path,
            original_ref=original_ref,
        )

    def _scan_package_source(
        self,
        source,
        lookup_keys,
        *,
        flakeref=None,
        walk_target=True,
        impure=False,
    ):
        scan_impure = impure or source.expression_impure
        cache_key = self._package_cache_key(
            source, lookup_keys, walk_target=walk_target, impure=scan_impure
        )
        lock_started = time.perf_counter()
        LOG.debug("Acquiring package metadata cache lock: %s", self.lock.lock_file)
        with self.lock:
            LOG.verbose(
                "Acquired package metadata cache lock in %.3fs",
                time.perf_counter() - lock_started,
            )
            if cache_key is None:
                LOG.verbose("Package metadata cache disabled; scanning")
            else:
                df = self.cache.get(cache_key)
                if df is not None:
                    LOG.verbose("Package metadata cache hit")
                    LOG.debug("found package metadata cache entry: %s", cache_key)
                    return df
                LOG.verbose("Package metadata cache miss; scanning")
                LOG.debug("cache miss, scanning package metadata: %s", cache_key)
            scan_started = time.perf_counter()
            scan = functools.partial(
                try_scan_package_meta,
                lookup_keys,
                flakeref=flakeref,
                nixpkgs_path=source.path,
                pkgs_expression=source.expression,
                impure=scan_impure,
            )
            df = scan(walk_target=walk_target)
            complete = df is not None
            if not complete and flakeref:
                # Evaluating the target or the package outputs of flake inputs
                # can fail in ways the Nix helper cannot catch.  Retry without
                # them, so the failure does not cost the remaining metadata.
                LOG.verbose(
                    "Package metadata scan failed; retrying without the "
                    "target walk and flake input packages"
                )
                df = scan(walk_target=False, search_inputs=False)
            LOG.verbose(
                "Package metadata scan returned %s row(s) in %.3fs",
                "failed" if df is None else len(df),
                time.perf_counter() - scan_started,
            )
            # A retry result is incomplete, and the failure can be temporary.
            if complete and cache_key is not None:
                self.cache.set(key=cache_key, value=df, ttl=_PACKAGE_META_TTL)
            return df

    @staticmethod
    def _package_cache_key(source, lookup_keys, *, walk_target=True, impure=False):
        """Return the cache key for one scan, or None when it is not cacheable."""
        if impure:
            return None
        if source.expression:
            source_key = source.expression_cache_key
        else:
            source_key = source.path or source.flakeref
        # The scan walks the target, so the key needs the locked target as well.
        if not source_key or not source.flakeref_cache_key:
            return None
        return (
            f"package-meta:{source_key}:flake:{source.flakeref_cache_key}:"
            f"fingerprint:{package_meta_cache_fingerprint()}:"
            f"lookups:{package_meta_candidate_key(lookup_keys)}:"
            f"walk:{int(walk_target)}"
        )


def _has_nixos_system(components):
    """Return true when the components include a NixOS system.

    A NixOS system references its packages only through string context, so
    walking a target that holds one finds next to nothing, while evaluating
    it a second time is slow and needs a lot of memory.
    """
    return bool(components[cols.NAME].astype(str).str.startswith("nixos-system-").any())


def _package_scan_flakeref(source, flakeref):
    return source.flakeref_cache_key or flakeref or source.flakeref
