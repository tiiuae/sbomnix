# From: https://github.com/flyingcircusio/vulnix/blob/1.10.1/LICENSE:
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Flying Circus Internet Operations GmbH

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

# pylint: disable=invalid-name
# pylint: disable=too-many-instance-attributes

"""Nix derivation, originally from https://github.com/flyingcircusio/vulnix"""

import bisect
import json

from packageurl import PackageURL

from common.log import LOG, LOG_SPAM
from common.nix_utils import parse_nix_derivation_show
from common.proc import exec_cmd, nix_cmd

###############################################################################


def load(path, outpath):
    """Load derivation from path"""
    drv_infos = parse_nix_derivation_show(
        exec_cmd(nix_cmd("derivation", "show", path)).stdout,
        store_path_hint=path,
    )
    drv_info = drv_infos.get(path)
    if drv_info is None and drv_infos:
        drv_info = next(iter(drv_infos.values()))
    if drv_info is None:
        raise RuntimeError(f"Failed loading derivation '{path}'")
    d_obj = Derive.from_nix_derivation_info(path, drv_info, outpath)
    LOG.log(LOG_SPAM, "load derivation: %s", d_obj)
    LOG.log(LOG_SPAM, "derivation attrs: %s", d_obj.to_dict())
    return d_obj


def destructure(env):
    """Decodes Nix 2.0 __structuredAttrs."""
    if "__json" in env:
        return json.loads(env["__json"])
    return {}


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
        outputs = envVars.get("outputs", "").split()
        for output in outputs:
            path = envVars.get(output, None)
            self.add_output_path(path)
        LOG.log(LOG_SPAM, "%s outputs: %s", self, self.outputs)
        # pname 'source' in Nix has special meaning - it is the default name
        # for all fetchFromGitHub derivations. As such, it should not be used
        # to construct cpe or purl, rather, cpe and purl should be empty
        # for such packages.
        self.cpe = ""
        self.purl = ""
        self._refresh_purl()
        self.urls = envVars.get("urls", "")

    @classmethod
    def from_nix_derivation_info(cls, path, drv_info, outpath=None):
        """Create a derivation from normalized `nix derivation show` JSON."""
        env_vars = dict(drv_info.get("env", {}))
        name = _coerce_derivation_string(drv_info.get("name")) or env_vars.get("name")
        if not name:
            name = destructure(env_vars).get("name")
        outputs = drv_info.get("outputs", {})
        if not isinstance(outputs, dict):
            outputs = {}
        drv = cls(
            envVars=env_vars,
            name=name,
            patches=env_vars.get("patches", ""),
        )
        drv.system = _coerce_derivation_string(drv_info.get("system")) or drv.system
        drv.version = env_vars.get("version", "")
        if not drv.version:
            drv.version = _coerce_derivation_string(drv_info.get("version"))
        drv.out = drv.out or _derivation_output_path(outputs, "out")
        drv._refresh_purl()
        drv.outputs = []
        _set_derivation_output_paths(drv, outputs, env_vars)
        drv.init(path, outpath)
        return drv

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

    def _refresh_purl(self):
        self.purl = ""
        if self.pname != "source":
            self.purl = str(
                PackageURL(type="nix", name=self.pname, version=self.version)
            )

    def to_dict(self):
        """Return derivation as dictionary"""
        ret = {}
        for attr in vars(self):
            ret[attr] = getattr(self, attr)
        return ret


def _derivation_output_path(outputs, output_name):
    output = outputs.get(output_name)
    if isinstance(output, dict):
        return output.get("path", "")
    if isinstance(output, str):
        return output
    return ""


def _coerce_derivation_string(value):
    if isinstance(value, str):
        return value
    return ""


def _set_derivation_output_paths(drv, outputs, env_vars):
    for output in outputs.values():
        if isinstance(output, dict):
            drv.add_output_path(output.get("path"))
        else:
            drv.add_output_path(output)
    if drv.outputs:
        return
    for output_name in str(env_vars.get("outputs", "")).split():
        drv.add_output_path(env_vars.get(output_name))
