# From: https://github.com/henrirosten/vulnix/blob/master/LICENSE:
# SPDX-FileCopyrightText: Flying Circus Internet Operations GmbH

# SPDX-FileCopyrightText: 2022 Unikie
#
# SPDX-License-Identifier: BSD-3-Clause

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

    def __init__(self, nix_path, runtime=False):
        _LOG.debug("")
        self.runtime = runtime
        self.derivations = set()
        self._add_path(nix_path)
        self.target_derivation = self._find_deriver(nix_path)

    def _find_deriver(self, path, qpi_deriver=None):
        _LOG.debug("")
        if path.endswith(".drv"):
            return path
        # Deriver from QueryPathInfo
        if qpi_deriver is None:
            qpi_deriver = exec_cmd(["nix-store", "-qd", path]).strip()
        _LOG.debug("qpi_deriver: %s", qpi_deriver)
        if (
            qpi_deriver
            and qpi_deriver != "unknown-deriver"
            and os.path.exists(qpi_deriver)
        ):
            return qpi_deriver
        # Deriver from QueryValidDerivers
        qvd_deriver = list(
            json.loads(exec_cmd(["nix", "show-derivation", path])).keys()
        )[0]
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

    def _find_outputs(self, path):
        _LOG.debug("")
        if not path.endswith(".drv"):
            return [path]

        result = []
        for drv in json.loads(exec_cmd(["nix", "show-derivation", path])).values():
            for output in drv.get("outputs").values():
                result.append(output.get("path"))
        return result

    def _add_path(self, path):
        """Add the closure of all derivations referenced by a store path."""
        _LOG.debug("")
        if not os.path.exists(path):
            raise RuntimeError(
                f"path `{path}` does not exist - cannot load "
                "derivations referenced from it"
            )
        _LOG.info('Loading derivations referenced by "%s"', path)

        if self.runtime:
            for output in self._find_outputs(path):
                for candidate in map(
                    # We cannot use the `deriver` field directly because
                    # like from `nix-store -qd` that path may not exist.
                    # However, we know that if it is not present
                    # the path has no deriver because it is a
                    # derivation input source so we can skip it.
                    lambda p: self._find_deriver(
                        p.get("path"), qpi_deriver=p.get("deriver")
                    )
                    if p.get("deriver") is not None
                    else None,
                    json.loads(exec_cmd(["nix", "path-info", "-r", "--json", output])),
                ):
                    if candidate is not None:
                        self._update(candidate)
        else:
            deriver = self._find_deriver(path)
            for candidate in exec_cmd(["nix-store", "-qR", deriver]).splitlines():
                self._update(candidate)

    def _update(self, drv_path):
        _LOG.debug("drv_path=%s", drv_path)
        if not drv_path.endswith(".drv"):
            return
        try:
            drv_obj = load(drv_path)
        except SkipDrv:
            return
        self.derivations.add(drv_obj)
        self.target_derivation = drv_path

    def get_target_drv_path(self):
        """Get the target derivation path"""
        _LOG.debug("path=%s", self.target_derivation)
        return self.target_derivation

    def to_dataframe(self):
        """Return store derivations as pandas dataframe"""
        _LOG.debug("")
        drv_dicts = [drv.to_dict() for drv in self.derivations]
        return pd.DataFrame.from_records(drv_dicts)
