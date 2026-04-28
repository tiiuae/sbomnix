# From: https://github.com/flyingcircusio/vulnix/blob/1.10.1/LICENSE:
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Flying Circus Internet Operations GmbH

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

"""Nix store, originally from https://github.com/flyingcircusio/vulnix"""

import os
from collections import defaultdict

import pandas as pd

from common.log import LOG, LOG_SPAM
from common.nix_utils import parse_nix_derivation_show
from common.proc import exec_cmd, nix_cmd
from sbomnix.cpe import CPE
from sbomnix.derivation import load, load_many

###############################################################################


class Store:
    """Nix store"""

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


def find_deriver(path):
    """Return drv path for the given nix store artifact path"""
    LOG.log(LOG_SPAM, path)
    if path.endswith(".drv"):
        return path
    # Deriver from QueryValidDerivers
    cmd = nix_cmd("derivation", "show", path)
    ret = exec_cmd(cmd, raise_on_error=False, log_error=False)
    if not ret:
        LOG.log(LOG_SPAM, "Deriver not found for '%s'", path)
        return None
    qvd_json_keys = list(
        parse_nix_derivation_show(ret.stdout, store_path_hint=path).keys()
    )
    if not qvd_json_keys or len(qvd_json_keys) < 1:
        LOG.log(LOG_SPAM, "Not qvd_deriver for '%s'", path)
        return None
    qvd_deriver = qvd_json_keys[0]
    LOG.log(LOG_SPAM, "qvd_deriver: %s", qvd_deriver)
    if qvd_deriver and os.path.exists(qvd_deriver):
        return qvd_deriver
    # Deriver from QueryPathInfo
    qpi_deriver = exec_cmd(["nix-store", "-qd", path]).stdout.strip()
    LOG.log(LOG_SPAM, "qpi_deriver: %s", qpi_deriver)
    if qpi_deriver and qpi_deriver != "unknown-deriver" and os.path.exists(qpi_deriver):
        return qpi_deriver

    error = ""
    if qpi_deriver and qpi_deriver != "unknown-deriver":
        error += f"Deriver `{qpi_deriver}` does not exist.  "
    if qvd_deriver and qvd_deriver != qpi_deriver:
        error += f"Deriver `{qvd_deriver}` does not exist.  "
    if error:
        raise RuntimeError(error + f"Couldn't find deriver for path `{path}`")
    raise RuntimeError(
        "Cannot determine deriver. Is this really a path into the nix store?",
        path,
    )


def find_derivers(paths, batch_size=500):
    """Return drv paths for many store artifacts, batching `nix-store -qd`."""
    resolved = {}
    non_drv_paths = []
    for path in paths:
        if path.endswith(".drv"):
            resolved[path] = path
        else:
            non_drv_paths.append(path)
    if not non_drv_paths:
        return resolved
    for start in range(0, len(non_drv_paths), batch_size):
        batch = non_drv_paths[start : start + batch_size]
        ret = exec_cmd(
            ["nix-store", "-qd", *batch], raise_on_error=False, log_error=False
        )
        if ret:
            lines = ret.stdout.splitlines()
            if len(lines) == len(batch):
                for path, drv_path in zip(batch, lines, strict=True):
                    if (
                        drv_path
                        and drv_path != "unknown-deriver"
                        and os.path.exists(drv_path)
                    ):
                        resolved[path] = drv_path
                        continue
                    resolved[path] = find_deriver(path)
                continue
            LOG.debug(
                "nix-store -qd returned %d lines for %d paths; falling back to per-path lookup",
                len(lines),
                len(batch),
            )
        for path in batch:
            resolved[path] = find_deriver(path)
    return resolved


###############################################################################
