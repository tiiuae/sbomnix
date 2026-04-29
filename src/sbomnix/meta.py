# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Cache and scan nixpkgs meta information."""

import pathlib
import tempfile
from dataclasses import replace
from getpass import getuser

from filelock import FileLock

from common.log import LOG
from nixmeta.scanner import NixMetaScanner
from sbomnix.dfcache import LockedDfCache
from sbomnix.meta_source import (
    META_NIXPKGS_NIX_PATH,
    SCAN_EXCEPTIONS,
    NixpkgsMetaSource,
    NixpkgsMetaSourceResolver,
    classify_meta_nixpkgs,
)

###############################################################################

# Update locally generated nixpkgs meta-info every 30 days or when local cache
# is cleaned.
_NIXMETA_NIXPKGS_TTL = 60 * 60 * 24 * 30

# FileLock lock path
_FLOCK = pathlib.Path(tempfile.gettempdir()) / f"{getuser()}_sbomnix_meta.lock"

###############################################################################

__all__ = [
    "META_NIXPKGS_NIX_PATH",
    "Meta",
    "NixpkgsMetaSource",
    "classify_meta_nixpkgs",
]


class Meta:
    """Cache nixpkgs meta information."""

    def __init__(self):
        self.lock = FileLock(_FLOCK)
        self.cache = LockedDfCache()
        self.source_resolver = NixpkgsMetaSourceResolver()

    def get_nixpkgs_meta(self, nixref=None):
        """
        Return nixpkgs meta pinned in `nixref`. `nixref` can point to a
        nix store path or flake reference. If nixref is None, attempt to
        read the nixpkgs store path from NIX_PATH environment variable.
        """
        source = self.source_resolver.resolve_default_source(nixref)
        return self._scan_source(source)

    def get_nixpkgs_meta_with_source(
        self,
        *,
        target_path=None,
        flakeref=None,
        original_ref=None,
        explicit_nixpkgs=None,
        impure=False,
    ):
        """Return nixpkgs metadata and selected metadata source."""
        source = self._resolve_source(
            target_path=target_path,
            flakeref=flakeref,
            original_ref=original_ref,
            explicit_nixpkgs=explicit_nixpkgs,
            impure=impure,
        )
        return self._scan_source_with_source(source)

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
            return self.source_resolver.resolve_flakeref_lock_source(flakeref)

        return self.source_resolver.path_target_without_source(
            target_path=target_path,
            original_ref=original_ref,
        )

    def _scan_source(self, source):
        df, _source = self._scan_source_with_source(source)
        return df

    def _scan_source_with_source(self, source):
        if not source.path:
            return None, source
        if source.expression:
            LOG.debug("Scanning meta-info using nix expression for: %s", source.path)
            df = self._scan_expression(
                source.expression,
                cache_key=source.expression_cache_key,
                impure=source.expression_impure,
            )
            if df is not None and not df.empty:
                return df, source
            LOG.warning(
                "Failed scanning evaluated package set: %s",
                source.path,
            )
            return None, replace(
                source,
                message=(
                    "Evaluated package-set metadata scan failed. "
                    "Skipping nixpkgs metadata."
                ),
            )
        LOG.debug("Scanning meta-info using nixpkgs path: %s", source.path)
        return self._scan(source.path), source

    def _scan_expression(self, expression, *, cache_key=None, impure=False):
        if cache_key is None:
            with self.lock:
                LOG.debug("cache disabled, scanning expression")
                df = self._try_scan_expression(expression, impure=impure)
                if df is None or df.empty:
                    LOG.warning("Failed scanning uncached nixmeta expression")
                    return None
                return df
        cache_key = f"expr:{cache_key}"
        with self.lock:
            df = self.cache.get(cache_key)
            if df is not None and not df.empty:
                LOG.debug("found from cache: %s", cache_key)
                return df
            LOG.debug("cache miss, scanning expression: %s", cache_key)
            df = self._try_scan_expression(expression, impure=impure)
            if df is None or df.empty:
                LOG.warning("Failed scanning nixmeta expression: %s", cache_key)
                return None
            self.cache.set(key=cache_key, value=df, ttl=_NIXMETA_NIXPKGS_TTL)
            return df

    @staticmethod
    def _try_scan_expression(expression, *, impure=False):
        try:
            scanner = NixMetaScanner()
            scanner.scan_expression(expression, impure=impure)
            return scanner.to_df()
        except SCAN_EXCEPTIONS:
            LOG.debug("Failed scanning nixmeta expression", exc_info=True)
            return None

    def _scan(self, nixpkgs_path):
        # In case sbomnix is run concurrently, we want to make sure there's
        # only one instance of NixMetaScanner.scan_path() running at a time.
        # The reason is, NixMetaScanner.scan_path() potentially invokes
        # `nix-env -qa --meta --json -f /path/to/nixpkgs` which is very
        # memory intensive. The locking needs to happen here (and not in
        # NixMetaScanner) because this object caches the nixmeta info.
        # First scan generates the cache, after which the consecutive scans
        # will read the scan results from the cache, not having to run
        # the nix-env command again, making the consecutive scans relatively
        # fast and light-weight.
        with self.lock:
            df = self.cache.get(nixpkgs_path)
            if df is not None and not df.empty:
                LOG.debug("found from cache: %s", nixpkgs_path)
                return df
            LOG.debug("cache miss, scanning: %s", nixpkgs_path)
            scanner = NixMetaScanner()
            scanner.scan_path(nixpkgs_path)
            df = scanner.to_df()
            if df is None or df.empty:
                LOG.warning("Failed scanning nixmeta: %s", nixpkgs_path)
                return None
            # Cache requires some TTL, so we set it to some value here.
            # Although, we could as well store it indefinitely as it should
            # not change given the same key (nixpkgs store path).
            self.cache.set(key=nixpkgs_path, value=df, ttl=_NIXMETA_NIXPKGS_TTL)
            return df


###############################################################################
