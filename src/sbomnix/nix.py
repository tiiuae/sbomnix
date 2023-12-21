# From: https://github.com/flyingcircusio/vulnix/blob/1.10.1/LICENSE:
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Flying Circus Internet Operations GmbH

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

""" Nix store, originally from https://github.com/flyingcircusio/vulnix """

import os
import json
import pandas as pd

from common.utils import LOG, LOG_SPAM, exec_cmd
from sbomnix.derivation import load

###############################################################################


class Store:
    """Nix store"""

    def __init__(self, buildtime=False):
        self.buildtime = buildtime
        self.derivations = {}

    def _add_cached(self, path, drv):
        LOG.log(LOG_SPAM, "caching path - %s:%s", path, drv)
        self.derivations[path] = drv

    def _is_cached(self, path):
        cached = path in self.derivations
        LOG.log(LOG_SPAM, "is cached %s:%s", path, cached)
        return path in self.derivations

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
            drv_obj = load(drv_path)
            self._add_cached(drv_path, drv=drv_obj)
        assert drv_obj.store_path == drv_path, f"unexpected drv_path: {drv_path}"
        if nixpath:
            # We end up here if the nix artifact read from output path 'nixpath'
            # does not have it's own deriver, but it's produced by another
            # deriver. This happens because 'drv_obj' is associated to more
            # than one outputs:
            drv_obj.add_output_path(nixpath)
            self._add_cached(nixpath, drv=drv_obj)

    def add_path(self, nixpath):
        """Add the derivation referenced by a store path (nixpath)"""
        LOG.log(LOG_SPAM, nixpath)
        if self._is_cached(nixpath):
            LOG.log(LOG_SPAM, "Skipping redundant path '%s'", nixpath)
            return
        if not os.path.exists(nixpath):
            raise RuntimeError(
                f"path `{nixpath}` does not exist - cannot load "
                "derivations referenced from it"
            )
        drv_path = find_deriver(nixpath)
        if not drv_path:
            LOG.log(LOG_SPAM, "No deriver found for: '%s", nixpath)
            self._add_cached(nixpath, drv=None)
            return
        self._update(drv_path, nixpath)
        if self.buildtime:
            ret = exec_cmd(["nix-store", "-qR", drv_path])
            for candidate in ret.stdout.splitlines():
                self._update(candidate)

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
    ret = exec_cmd(
        ["nix", "derivation", "show", path], raise_on_error=False, loglevel=LOG_SPAM
    )
    if not ret:
        LOG.log(LOG_SPAM, "Deriver not found for '%s'", path)
        return None
    qvd_json_keys = list(json.loads(ret.stdout).keys())
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


###############################################################################
