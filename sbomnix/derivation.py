# From: https://github.com/flyingcircusio/vulnix/blob/1.10.1/LICENSE:
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Flying Circus Internet Operations GmbH

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

# pylint: disable=unnecessary-pass, invalid-name, eval-used
# pylint: disable=too-many-instance-attributes

""" Nix derivation, originally from https://github.com/flyingcircusio/vulnix """

import json
import logging
import bisect
from packageurl import PackageURL
from sbomnix.cpe import CPE

from sbomnix.utils import (
    LOGGER_NAME,
    LOG_SPAM,
)

###############################################################################

_LOG = logging.getLogger(LOGGER_NAME)

###############################################################################


def load(path):
    """Load derivation from path"""
    _LOG.debug("")
    with open(path, encoding="utf-8") as f:
        d_obj = eval(f.read(), {"__builtins__": {}, "Derive": Derive}, {})
    d_obj.store_path = path
    _LOG.debug("load derivation: %s", d_obj)
    _LOG.log(LOG_SPAM, "deivation attrs: %s", d_obj.to_dict())
    return d_obj


def destructure(env):
    """Decodes Nix 2.0 __structuredAttrs."""
    return json.loads(env["__json"])


class Derive:
    """Nix derivation as found as .drv files in the Nix store."""

    store_path = None

    def __init__(
        self,
        _outputs=None,
        _inputDrvs=None,
        _inputSrcs=None,
        _system=None,
        _builder=None,
        _args=None,
        envVars=None,
        _derivations=None,
        name=None,
        patches=None,
    ):
        """Create a derivation from a .drv file.

        The derivation files are just accidentally Python-syntax, but
        hey! :-)
        """
        if envVars is None:
            envVars = {}
        envVars = dict(envVars)
        _LOG.log(LOG_SPAM, envVars)
        self.name = name or envVars.get("name")
        if not self.name:
            self.name = destructure(envVars)["name"]

        pname = envVars.get("pname", self.name)
        # pname read from envVars might not match the pname in nixpkgs.
        # As an example 'Authen-SASL' full pname is 'perl5.36.0-Authen-SASL'
        # Below, we reconstruct the full pname based on self.name which
        # contains the full pname:
        self.pname = self.name.partition(pname)[0] + pname
        self.version = envVars.get("version", "")
        self.patches = patches or envVars.get("patches", "")
        self.system = envVars.get("system", "")
        self.outputs = [envVars.get("out", "")]
        # pname 'source' in Nix has special meaning - it is the default name
        # for all fetchFromGitHub derivations. As such, it should not be used
        # to construct cpe or purl, rather, cpe and purl should be empty
        # for such packages.
        self.cpe = ""
        self.purl = ""
        if self.pname != "source":
            self.cpe = CPE().generate(self.pname, self.version)
            self.purl = str(
                PackageURL(type="nix", name=self.pname, version=self.version)
            )
        self.urls = envVars.get("urls", "")

    def __repr__(self):
        return f"<Derive({repr(self.name)})>"

    def add_output_path(self, path):
        """Add an output path to derivation"""
        if path not in self.outputs and path != self.store_path:
            _LOG.debug("adding outpath to %s:%s", self, path)
            bisect.insort(self.outputs, path)

    def to_dict(self):
        """Return derivation as dictionary"""
        ret = {}
        for attr in vars(self):
            ret[attr] = getattr(self, attr)
        return ret
