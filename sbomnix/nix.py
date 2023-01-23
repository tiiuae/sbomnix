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

    def _update(self, drv_path, in_path=None):
        _LOG.debug("drv_path=%s", drv_path)
        if drv_path in self.derivations:
            _LOG.debug("Skipping redundant path '%s'", drv_path)
            return
        if not drv_path.endswith(".drv"):
            _LOG.debug("Not a derivation, skipping: '%s'", drv_path)
            self.derivations[drv_path] = None
            return
        try:
            drv_obj = load(drv_path)
        except SkipDrv:
            _LOG.debug("Skipping derivation: '%s'", drv_path)
            self.derivations[drv_path] = None
            return
        if in_path and in_path != drv_obj.store_path and in_path != drv_obj.out:
            # We end up here if the nix artifact read from 'in_path' does
            # not have it's own deriver, but it's produced by another
            # deriver. As an example, 'util-linux-minimal-2.38.1-lib' deriver
            # is 'util-linux-minimal-2.38.1', so whenever a component depends
            # on 'util-linux-minimal-2.38.1-lib' the dependency in sbom will
            # be replaced with dependency to 'util-linux-minimal-2.38.1' because
            # that's the deriver for 'util-linux-minimal-2.38.1-lib'.
            # To make the sbomdb dependency lookup find the dependencies for
            # such cases correctly, we need to fix the drv path so that it points
            # to the store path of util-linux-minimal-2.38.1-lib, not the path of
            # util-linux-minimal-2.38.1:
            if in_path.endswith(".drv"):
                _LOG.debug("Fix store_path: %s ==> %s", drv_obj.store_path, in_path)
                drv_obj.store_path = in_path
            else:
                _LOG.debug("Fix out path: %s ==> %s", drv_obj.out, in_path)
                drv_obj.out = in_path
        self.derivations[drv_obj.store_path] = drv_obj
        self.derivations[drv_obj.out] = drv_obj

    def add_path(self, path):
        """Add the the derivation referenced by a store path"""
        _LOG.debug(path)
        if path in self.derivations:
            _LOG.debug("Skipping redundant path '%s'", path)
            return
        if not os.path.exists(path):
            raise RuntimeError(
                f"path `{path}` does not exist - cannot load "
                "derivations referenced from it"
            )
        deriver = find_deriver(path)
        if not deriver:
            _LOG.debug("No deriver found for: '%s", path)
            self.derivations[path] = None
            return
        self._update(deriver, path)
        if self.buildtime:
            for candidate in exec_cmd(["nix-store", "-qR", deriver]).splitlines():
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
