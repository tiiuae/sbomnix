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

    def __init__(self, nix_path, runtime=False):
        _LOG.debug(nix_path)
        self.runtime = runtime
        self.derivations = set()
        self._add_path(nix_path)
        self.target_derivation = self._find_deriver(nix_path)

    def _find_deriver(self, path, qpi_deriver=None):
        _LOG.debug(path)
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

    def _find_path_info_deriver(self, path_info):
        _LOG.log(LOG_SPAM, "path_info: %s", path_info)
        return self._find_deriver(
            path_info.get("path"), qpi_deriver=path_info.get("deriver")
        )

    def _find_outputs(self, path):
        _LOG.debug(path)
        if not path.endswith(".drv"):
            return [path]

        result = []
        for drv in json.loads(exec_cmd(["nix", "show-derivation", path])).values():
            for output in drv.get("outputs").values():
                result.append(output.get("path"))
        return result

    def _add_path(self, path):
        """Add the closure of all derivations referenced by a store path."""
        _LOG.debug(path)
        if not os.path.exists(path):
            raise RuntimeError(
                f"path `{path}` does not exist - cannot load "
                "derivations referenced from it"
            )
        _LOG.info('Loading derivations referenced by "%s"', path)

        if self.runtime:
            for output in self._find_outputs(path):
                _LOG.debug(output)
                ret = exec_cmd(
                    [
                        "nix",
                        "--extra-experimental-features",
                        "nix-command",
                        "path-info",
                        "-r",
                        "--json",
                        output,
                    ]
                )
                path_info_list = json.loads(ret)
                for candidate in map(self._find_path_info_deriver, path_info_list):
                    if candidate is not None:
                        self._update(candidate)
        else:
            deriver = self._find_deriver(path)
            if not deriver:
                _LOG.fatal("No deriver found for: '%s", path)
                return
            for candidate in exec_cmd(["nix-store", "-qR", deriver]).splitlines():
                self._update(candidate)

    def _update(self, drv_path):
        _LOG.debug("drv_path=%s", drv_path)
        if not drv_path.endswith(".drv"):
            _LOG.debug("Not a derivation, skipping: '%s'", drv_path)
            return
        try:
            drv_obj = load(drv_path)
        except SkipDrv:
            _LOG.debug("Skipping derivation: '%s'", drv_path)
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
