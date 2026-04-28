# From: https://github.com/flyingcircusio/vulnix/blob/1.10.1/LICENSE:
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Flying Circus Internet Operations GmbH

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

"""Fallback component loading from Nix store paths."""

import os
from collections import defaultdict

import pandas as pd

from common.log import LOG, LOG_SPAM
from sbomnix.cpe import CPE
from sbomnix.derivation import load, load_many
from sbomnix.derivers import find_derivers

###############################################################################


class FallbackStore:
    """Load component metadata when structured closure data is unavailable."""

    def __init__(self, buildtime=False, include_cpe=True):
        self.buildtime = buildtime
        self.derivations = {}
        self.cpe_generator = CPE(include_cpe=include_cpe)

    def _add_cached(self, path, drv):
        LOG.log(LOG_SPAM, "caching path - %s:%s", path, drv)
        self.derivations[path] = drv

    def _is_cached(self, path):
        cached = path in self.derivations
        LOG.log(LOG_SPAM, "is cached %s:%s", path, cached)
        return cached

    def _get_cached(self, path):
        LOG.log(LOG_SPAM, "get cached: %s", path)
        return self.derivations[path] if path in self.derivations else None

    def _update(self, drv_path, nixpath=None):
        LOG.log(LOG_SPAM, "drv_path=%s, nixpath=%s", drv_path, nixpath)
        if not drv_path.endswith(".drv"):
            LOG.log(LOG_SPAM, "Not a derivation, skipping: '%s'", drv_path)
            self._add_cached(drv_path, drv=None)
            return
        if nixpath and self._is_cached(nixpath):
            LOG.log(LOG_SPAM, "Skipping redundant nixpath '%s'", nixpath)
            return
        if not nixpath and self._is_cached(drv_path):
            LOG.log(LOG_SPAM, "Skipping redundant drvpath '%s'", drv_path)
            return
        drv_obj = self._get_cached(drv_path)
        if not drv_obj:
            drv_obj = load(drv_path, nixpath)
            drv_obj.set_cpe(self.cpe_generator)
            self._add_cached(drv_path, drv=drv_obj)
        assert drv_obj.store_path == drv_path, f"unexpected drv_path: {drv_path}"
        if nixpath:
            drv_obj.add_output_path(nixpath)
            self._add_cached(nixpath, drv=drv_obj)

    def add_path(self, nixpath):
        """Add the derivation referenced by a store path (nixpath)"""
        self.add_paths([nixpath])

    def _collect_pending_paths(self, nixpaths):
        """Split inputs into derivation paths and output paths needing lookup."""
        drv_output_paths = defaultdict(set)
        pending_output_paths = []
        for nixpath in nixpaths:
            LOG.log(LOG_SPAM, nixpath)
            if self._is_cached(nixpath):
                LOG.log(LOG_SPAM, "Skipping redundant path '%s'", nixpath)
                continue
            if not os.path.exists(nixpath):
                raise RuntimeError(
                    f"path `{nixpath}` does not exist - cannot load "
                    "derivations referenced from it"
                )
            if nixpath.endswith(".drv"):
                drv_output_paths.setdefault(nixpath, set())
                continue
            pending_output_paths.append(nixpath)
        return drv_output_paths, pending_output_paths

    def add_paths(self, nixpaths):
        """Add derivations referenced by the given store paths."""
        drv_output_paths, pending_output_paths = self._collect_pending_paths(nixpaths)

        for nixpath, drv_path in find_derivers(pending_output_paths).items():
            if not drv_path:
                LOG.log(LOG_SPAM, "No deriver found for: '%s", nixpath)
                self._add_cached(nixpath, drv=None)
                continue
            drv_output_paths[drv_path].add(nixpath)

        uncached_drv_paths = {
            drv_path for drv_path in drv_output_paths if not self._is_cached(drv_path)
        }
        if uncached_drv_paths:
            for drv_path, drv_obj in load_many(
                list(uncached_drv_paths),
                output_paths_by_drv=drv_output_paths,
            ).items():
                drv_obj.set_cpe(self.cpe_generator)
                self._add_cached(drv_path, drv=drv_obj)
                for output_path in drv_output_paths.get(drv_path, ()):
                    self._add_cached(output_path, drv=drv_obj)

        # Associate newly-seen output paths with derivations that were already
        # cached before this call (load_many handles the uncached ones above).
        for drv_path, output_paths in drv_output_paths.items():
            if drv_path in uncached_drv_paths:
                continue
            drv_obj = self._get_cached(drv_path)
            if not drv_obj:
                self._update(drv_path)
                drv_obj = self._get_cached(drv_path)
            for output_path in output_paths:
                if drv_obj:
                    drv_obj.add_output_path(output_path)
                self._add_cached(output_path, drv=drv_obj)

    def to_dataframe(self):
        """Return store derivations as pandas dataframe"""
        drv_dicts = [drv.to_dict() for drv in self.derivations.values() if drv]
        return pd.DataFrame.from_records(drv_dicts)


###############################################################################
