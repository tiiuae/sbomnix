# From: https://github.com/flyingcircusio/vulnix/blob/1.10.1/LICENSE:
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Flying Circus Internet Operations GmbH

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

# pylint: disable=invalid-name, eval-used
# pylint: disable=too-many-instance-attributes

""" Nix derivation, originally from https://github.com/flyingcircusio/vulnix """

import json
import bisect
from packageurl import PackageURL

from common.utils import LOG, LOG_SPAM


###############################################################################


def load(path, outpath):
    """Load derivation from path"""
    d_obj = None
    with open(path, encoding="utf-8") as f:
        d_obj = eval(f.read(), {"__builtins__": {}, "Derive": Derive}, {})
        d_obj.init(path, outpath)
        LOG.log(LOG_SPAM, "load derivation: %s", d_obj)
        LOG.log(LOG_SPAM, "derivation attrs: %s", d_obj.to_dict())
    return d_obj


def destructure(env):
    """Decodes Nix 2.0 __structuredAttrs."""
    return json.loads(env["__json"])


class Derive:
    """Nix derivation as found as .drv files in the Nix store."""

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
        LOG.log(LOG_SPAM, envVars)
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
        self.out = envVars.get("out", "")
        self.outputs = []
        self.store_path = None
        # pname 'source' in Nix has special meaning - it is the default name
        # for all fetchFromGitHub derivations. As such, it should not be used
        # to construct cpe or purl, rather, cpe and purl should be empty
        # for such packages.
        self.cpe = ""
        self.purl = ""
        if self.pname != "source":
            self.purl = str(
                PackageURL(type="nix", name=self.pname, version=self.version)
            )
        self.urls = envVars.get("urls", "")

    def init(self, path, outpath):
        """Initialize self.store_path and self.outputs"""
        assert self.store_path is None
        LOG.log(LOG_SPAM, "path:%s, outpath:%s", path, outpath)
        self.store_path = path
        outpath = outpath if outpath and outpath != path else self.out
        self.add_output_path(outpath)

    def __repr__(self):
        return f"<Derive({repr(self.name)})>"

    def set_cpe(self, cpe_generator):
        """Generate cpe identifier"""
        if self.pname != "source" and cpe_generator is not None:
            self.cpe = cpe_generator.generate(self.pname, self.version)

    def add_output_path(self, path):
        """Add an output path to derivation"""
        if path and path not in self.outputs and path != self.store_path:
            LOG.log(LOG_SPAM, "adding outpath to %s:%s", self, path)
            bisect.insort(self.outputs, path)

    def to_dict(self):
        """Return derivation as dictionary"""
        ret = {}
        for attr in vars(self):
            ret[attr] = getattr(self, attr)
        return ret
