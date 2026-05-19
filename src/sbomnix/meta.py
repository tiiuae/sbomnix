# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Cache and scan nixpkgs meta information."""

import re
from dataclasses import replace

import pandas as pd
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
_PACKAGE_META_FLAKE_INPUT_LOOKUP_LIMIT = 500
_PACKAGE_META_CACHE_REF_COLUMN = "_package_meta_cache_ref"
_PACKAGE_META_LOOKUP_ID_COLUMN = "_package_meta_lookup_id"

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
        explicit_nixpkgs=None,
        impure=False,
    ):
        """Return exact component metadata and selected metadata source."""
        source = self._resolve_source(
            target_path=target_path,
            flakeref=flakeref,
            original_ref=original_ref,
            explicit_nixpkgs=explicit_nixpkgs,
            impure=impure,
        )
        component_count = 0 if components is None else len(components)
        LOG.verbose("Resolving package metadata for %d component(s)", component_count)
        out_source = replace(
            source,
            method=f"{source.method}+{PACKAGE_META_METHOD}",
        )
        if not source.path and not source.expression and not flakeref:
            return None, source
        scan_flakeref = _package_scan_flakeref(source, flakeref)
        lookup_keys = package_meta_lookup_keys_for_components(
            components,
            target_path=target_path,
            flakeref=scan_flakeref,
        )
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
            flakeref=scan_flakeref,
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
        if scan_flakeref:
            df = self._add_flake_input_package_meta(
                components,
                df,
                source,
                flakeref=scan_flakeref,
                buildtime=buildtime,
                impure=impure,
            )
        if df.empty:
            return None, replace(
                out_source,
                message=(
                    "No package metadata matched component derivation "
                    "or output paths. Skipping nixpkgs metadata."
                ),
            )
        LOG.verbose("Matched nixpkgs metadata for %d component(s)", len(df))
        return df, out_source

    def _add_flake_input_package_meta(  # noqa: PLR0913
        self,
        components,
        df,
        source,
        *,
        flakeref,
        buildtime,
        impure,
    ):
        unmatched = _components_without_package_matches(components, df)
        if unmatched is None or unmatched.empty:
            return df

        lookup_keys = package_meta_lookup_keys_for_components(unmatched)
        if not lookup_keys:
            return df
        if len(lookup_keys) > _PACKAGE_META_FLAKE_INPUT_LOOKUP_LIMIT:
            LOG.debug(
                "Skipping flake-input metadata scan for %d unmatched lookup(s)",
                len(lookup_keys),
            )
            return df
        LOG.verbose(
            "Looking up flake input metadata for %d unmatched package name(s)",
            len(lookup_keys),
        )

        df_candidates = self._scan_package_source(
            source,
            lookup_keys,
            flakeref=flakeref,
            input_roots_only=True,
            impure=impure,
        )
        df_input = match_package_metadata_to_components(
            unmatched,
            df_candidates,
            buildtime=buildtime,
        )
        if df_input.empty:
            return df
        if df.empty:
            return df_input
        return pd.concat([df, df_input], ignore_index=True)

    def _resolve_source(
        self,
        *,
        target_path=None,
        flakeref=None,
        original_ref=None,
        explicit_nixpkgs=None,
        impure=False,
    ):
        if explicit_nixpkgs:
            return self.source_resolver.resolve_meta_nixpkgs_option(
                explicit_nixpkgs,
                target_path=target_path,
            )
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
        input_roots_only=False,
        impure=False,
    ):
        scan_impure = impure or source.expression_impure
        with self.lock:
            cache_scope = self._package_cache_scope(
                source,
                flakeref=flakeref,
                input_roots_only=input_roots_only,
                impure=scan_impure,
            )
            exact_cache_key = None
            df_cached = pd.DataFrame()
            missing_lookup_keys = list(lookup_keys)
            hit_count = 0
            if cache_scope is not None:
                exact_cache_key = self._package_scan_cache_key(
                    cache_scope,
                    lookup_keys,
                )
                df = self.cache.get(exact_cache_key)
                if df is not None:
                    LOG.verbose(
                        "Package metadata cache hit for %d package name(s)",
                        len(lookup_keys),
                    )
                    LOG.debug(
                        "found exact package metadata cache entry: %s", exact_cache_key
                    )
                    return df

                (
                    df_cached,
                    missing_lookup_keys,
                    hit_count,
                ) = self._cached_package_metadata(
                    cache_scope,
                    lookup_keys,
                )
                if not missing_lookup_keys:
                    LOG.verbose(
                        "Package metadata cache hit for %d package name(s)",
                        len(lookup_keys),
                    )
                    LOG.debug(
                        "found package metadata cache references: %s", cache_scope
                    )
                    return df_cached
                if hit_count:
                    LOG.verbose(
                        "Package metadata cache partial hit for %d/%d package name(s); "
                        "scanning %d",
                        hit_count,
                        len(lookup_keys),
                        len(missing_lookup_keys),
                    )
                    LOG.debug(
                        "partial package metadata cache hit: %s",
                        cache_scope,
                    )
                else:
                    LOG.verbose(
                        "Package metadata cache miss for %d package name(s); scanning",
                        len(lookup_keys),
                    )
                    LOG.debug("cache miss, scanning package metadata: %s", cache_scope)
            else:
                LOG.verbose(
                    "Package metadata cache disabled for %d package name(s); scanning",
                    len(lookup_keys),
                )
                LOG.debug(
                    "cache disabled, scanning package metadata for %d lookup(s)",
                    len(lookup_keys),
                )
            df = try_scan_package_meta(
                missing_lookup_keys,
                flakeref=_package_scan_flakeref(source, flakeref),
                nixpkgs_path=source.path,
                pkgs_expression=source.expression,
                input_roots_only=input_roots_only,
                impure=scan_impure,
            )
            if df is None:
                return None
            result = _concat_package_metadata_frames([df_cached, df])
            if cache_scope is not None:
                self._store_package_metadata(
                    cache_scope,
                    missing_lookup_keys,
                    df,
                )
                if hit_count and exact_cache_key is not None:
                    self.cache.set(
                        key=exact_cache_key,
                        value=result,
                        ttl=_PACKAGE_META_TTL,
                    )
                    LOG.debug(
                        "Stored combined package metadata cache entry: %s",
                        exact_cache_key,
                    )
            return result

    def _cached_package_metadata(self, cache_scope, lookup_keys):
        lookup_cache_items = [
            (self._package_lookup_cache_id(lookup_key), lookup_key)
            for lookup_key in lookup_keys
        ]
        df_index = self.cache.get(self._package_lookup_index_cache_key(cache_scope))
        ref_key_by_lookup_id = _package_lookup_index_refs(df_index)
        missing_lookup_keys = []
        ref_keys = set()
        hit_count = 0

        for lookup_id, lookup_key in lookup_cache_items:
            ref_key = ref_key_by_lookup_id.get(lookup_id)
            if not ref_key:
                missing_lookup_keys.append(lookup_key)
                continue
            ref_keys.add(ref_key)

        cached_ref_frames = _cache_get_many(self.cache, sorted(ref_keys))
        ref_frames = []
        seen_ref_keys = set()
        for lookup_id, lookup_key in lookup_cache_items:
            ref_key = ref_key_by_lookup_id.get(lookup_id)
            if not ref_key:
                continue
            df_ref = cached_ref_frames.get(ref_key)
            if df_ref is None:
                missing_lookup_keys.append(lookup_key)
                continue
            hit_count += 1
            if ref_key in seen_ref_keys:
                continue
            seen_ref_keys.add(ref_key)
            ref_frames.append(df_ref)

        return (
            _concat_package_metadata_frames(ref_frames),
            missing_lookup_keys,
            hit_count,
        )

    def _store_package_metadata(self, cache_scope, lookup_keys, df):
        if not lookup_keys:
            return
        scan_cache_key = self._package_scan_cache_key(cache_scope, lookup_keys)
        self.cache.set(key=scan_cache_key, value=df, ttl=_PACKAGE_META_TTL)
        self._store_package_lookup_index(cache_scope, lookup_keys, scan_cache_key)
        LOG.debug(
            "Stored package metadata cache group for %d lookup(s): %s",
            len(lookup_keys),
            scan_cache_key,
        )

    def _store_package_lookup_index(self, cache_scope, lookup_keys, scan_cache_key):
        index_cache_key = self._package_lookup_index_cache_key(cache_scope)
        df_index = self.cache.get(index_cache_key)
        df_new = pd.DataFrame(
            [
                {
                    _PACKAGE_META_LOOKUP_ID_COLUMN: self._package_lookup_cache_id(
                        lookup_key
                    ),
                    _PACKAGE_META_CACHE_REF_COLUMN: scan_cache_key,
                }
                for lookup_key in lookup_keys
            ]
        )
        df_index = _merge_package_lookup_index(df_index, df_new)
        self.cache.set(key=index_cache_key, value=df_index, ttl=_PACKAGE_META_TTL)

    @staticmethod
    def _package_cache_scope(
        source,
        *,
        flakeref=None,
        input_roots_only=False,
        impure=False,
    ):
        if impure:
            return None
        if source.expression:
            source_key = source.expression_cache_key
        else:
            source_key = source.path or source.flakeref
        if not source_key:
            return None
        flakeref_key = _package_cache_flake_key(
            source,
            flakeref,
            require_stable=not source.expression,
        )
        if flakeref_key is None:
            return None
        mode = "flake-inputs-only" if input_roots_only else "base"
        return (
            f"package-meta:{source_key}:flake:{flakeref_key}:mode:{mode}:"
            f"fingerprint:{package_meta_cache_fingerprint()}"
        )

    @classmethod
    def _package_cache_key(
        cls,
        source,
        lookup_keys,
        *,
        flakeref=None,
        input_roots_only=False,
        impure=False,
    ):
        cache_scope = cls._package_cache_scope(
            source,
            flakeref=flakeref,
            input_roots_only=input_roots_only,
            impure=impure,
        )
        if cache_scope is None:
            return None
        return cls._package_scan_cache_key(cache_scope, lookup_keys)

    @staticmethod
    def _package_scan_cache_key(cache_scope, lookup_keys):
        return f"{cache_scope}:lookups:{package_meta_candidate_key(lookup_keys)}"

    @staticmethod
    def _package_lookup_index_cache_key(cache_scope):
        return f"{cache_scope}:lookup-index"

    @staticmethod
    def _package_lookup_cache_id(lookup_key):
        return package_meta_candidate_key([lookup_key])


def _stable_flakeref_for_package_cache(flakeref):
    flake, _separator, _attr = str(flakeref or "").partition("#")
    return (
        flake.startswith("/nix/store/")
        or flake.startswith("path:/nix/store/")
        or re.search(r"(?:[?&])(?:narHash|rev)=", flake) is not None
    )


def _components_without_package_matches(components, package_meta):
    if components is None or components.empty:
        return components
    if package_meta is None or package_meta.empty:
        return components
    matched = set(package_meta[cols.STORE_PATH].astype(str))
    return components[~components[cols.STORE_PATH].astype(str).isin(matched)]


def _package_scan_flakeref(source, flakeref):
    return source.flakeref_cache_key or flakeref or source.flakeref


def _package_cache_flakeref_key(source, flakeref, *, require_stable):
    if source.flakeref_cache_key:
        return source.flakeref_cache_key
    flakeref_key = flakeref or source.flakeref or ""
    if (
        not flakeref_key
        or not require_stable
        or _stable_flakeref_for_package_cache(flakeref_key)
    ):
        return flakeref_key
    return None


def _package_cache_flake_key(source, flakeref, *, require_stable):
    flakeref_key = _package_cache_flakeref_key(
        source,
        flakeref,
        require_stable=require_stable,
    )
    if flakeref_key is None:
        return None
    flake, _separator, _attr = str(flakeref_key).partition("#")
    return flake


def _package_lookup_index_refs(df):
    if (
        df is None
        or df.empty
        or _PACKAGE_META_LOOKUP_ID_COLUMN not in df.columns
        or _PACKAGE_META_CACHE_REF_COLUMN not in df.columns
    ):
        return {}
    refs = {}
    df = df[[_PACKAGE_META_LOOKUP_ID_COLUMN, _PACKAGE_META_CACHE_REF_COLUMN]].dropna()
    for row in df.itertuples(index=False):
        lookup_id = str(row[0] or "")
        ref_key = str(row[1] or "")
        if lookup_id and ref_key:
            refs[lookup_id] = ref_key
    return refs


def _merge_package_lookup_index(df_index, df_new):
    frames = [
        frame for frame in (df_index, df_new) if frame is not None and not frame.empty
    ]
    if not frames:
        return pd.DataFrame(
            {
                _PACKAGE_META_LOOKUP_ID_COLUMN: pd.Series(dtype="object"),
                _PACKAGE_META_CACHE_REF_COLUMN: pd.Series(dtype="object"),
            }
        )
    return (
        pd.concat(frames, ignore_index=True)
        .dropna(subset=[_PACKAGE_META_LOOKUP_ID_COLUMN, _PACKAGE_META_CACHE_REF_COLUMN])
        .drop_duplicates(subset=[_PACKAGE_META_LOOKUP_ID_COLUMN], keep="last")
        .reset_index(drop=True)
    )


def _cache_get_many(cache, keys):
    if not keys:
        return {}
    get_many = getattr(cache, "get_many", None)
    if get_many is not None:
        return get_many(keys)
    return {key: cache.get(key) for key in keys}


def _concat_package_metadata_frames(frames):
    frames = [frame for frame in frames if frame is not None and not frame.empty]
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True).drop_duplicates(ignore_index=True)
