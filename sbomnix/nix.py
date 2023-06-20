# From: https://github.com/flyingcircusio/vulnix/blob/1.10.1/LICENSE:
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Flying Circus Internet Operations GmbH

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

""" Nix store, originally from https://github.com/flyingcircusio/vulnix """

import os
import logging
import json
import pandas as pd

from sbomnix.utils import (
    LOGGER_NAME,
    LOG_SPAM,
    exec_cmd,
)

from sbomnix.derivation import (
    load,
    SkipDrv,
)

###############################################################################

_LOG = logging.getLogger(LOGGER_NAME)

###############################################################################


class Store:
    """Nix store"""

    def __init__(self, buildtime=False):
        self.buildtime = buildtime
        self.derivations = {}

    def _add_cached(self, path, drv):
        _LOG.log(LOG_SPAM, "caching path - %s:%s", path, drv)
        self.derivations[path] = drv

    def _is_cached(self, path):
        cached = path in self.derivations
        _LOG.log(LOG_SPAM, "is cached %s:%s", path, cached)
        return path in self.derivations

    def _get_cached(self, path):
        _LOG.log(LOG_SPAM, "get cached: %s", path)
        return self.derivations[path] if path in self.derivations else None

    def _update(self, drv_path, nixpath=None):
        _LOG.debug("drv_path=%s, nixpath=%s", drv_path, nixpath)
        if not drv_path.endswith(".drv"):
            _LOG.debug("Not a derivation, skipping: '%s'", drv_path)
            self._add_cached(drv_path, drv=None)
            return
        if nixpath and self._is_cached(nixpath):
            _LOG.debug("Skipping redundant nixpath '%s'", nixpath)
            return
        if not nixpath and self._is_cached(drv_path):
            _LOG.debug("Skipping redundant drvpath '%s'", drv_path)
            return
        drv_obj = self._get_cached(drv_path)
        if not drv_obj:
            try:
                drv_obj = load(drv_path)
                self._add_cached(drv_path, drv=drv_obj)
            except SkipDrv:
                _LOG.debug("Skipping derivation: '%s'", drv_path)
                self._add_cached(drv_path, drv=None)
                return
        assert drv_obj.store_path == drv_path, f"unexpected drv_path: {drv_path}"
        if nixpath:
            # We end up here if the nix artifact read from out path 'nixpath'
            # does not have it's own deriver, but it's produced by another
            # deriver. This happens because 'drv_obj' is associated to more
            # than one 'out' path:
            drv_obj.add_outpath(nixpath)
            self._add_cached(nixpath, drv=drv_obj)

    def add_path(self, nixpath):
        """Add the derivation referenced by a store path (nixpath)"""
        _LOG.debug(nixpath)
        if self._is_cached(nixpath):
            _LOG.debug("Skipping redundant path '%s'", nixpath)
            return
        if not os.path.exists(nixpath):
            raise RuntimeError(
                f"path `{nixpath}` does not exist - cannot load "
                "derivations referenced from it"
            )
        drv_path = find_deriver(nixpath)
        if not drv_path:
            _LOG.debug("No deriver found for: '%s", nixpath)
            self._add_cached(nixpath, drv=None)
            return
        self._update(drv_path, nixpath)
        if self.buildtime:
            for candidate in exec_cmd(["nix-store", "-qR", drv_path]).splitlines():
                self._update(candidate)

    def to_dataframe(self):
        """Return store derivations as pandas dataframe"""
        _LOG.debug("")
        drv_dicts = [drv.to_dict() for drv in self.derivations.values() if drv]
        return pd.DataFrame.from_records(drv_dicts)


###############################################################################


def find_deriver(path):
    """Return drv path for the given nix store artifact path"""
    _LOG.debug(path)
    if path.endswith(".drv"):
        return path
    # Deriver from QueryPathInfo
    qpi_deriver = exec_cmd(["nix-store", "-qd", path]).strip()
    _LOG.debug("qpi_deriver: %s", qpi_deriver)
    if qpi_deriver and qpi_deriver != "unknown-deriver" and os.path.exists(qpi_deriver):
        return qpi_deriver
    # Deriver from QueryValidDerivers
    ret = exec_cmd(["nix", "show-derivation", path], raise_on_error=False)
    if not ret:
        _LOG.debug("Deriver not found for '%s'", path)
        return None
    qvd_json_keys = list(json.loads(ret).keys())
    if not qvd_json_keys or len(qvd_json_keys) < 1:
        _LOG.debug("Not qvd_deriver for '%s'", path)
        return None
    qvd_deriver = qvd_json_keys[0]
    _LOG.debug("qvd_deriver: %s", qvd_deriver)
    if qvd_deriver and os.path.exists(qvd_deriver):
        return qvd_deriver

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
