# From: https://github.com/flyingcircusio/vulnix/blob/1.10.1/LICENSE:
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Flying Circus Internet Operations GmbH

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

"""Nix derivation, originally from https://github.com/flyingcircusio/vulnix"""

import bisect
import json
import subprocess
from itertools import islice

from packageurl import PackageURL

from common.errors import NixCommandError
from common.log import LOG, LOG_SPAM
from common.nix_utils import parse_nix_derivation_show
from common.proc import exec_cmd, nix_cmd

###############################################################################


def _batched(iterable, size):
    iterator = iter(iterable)
    while batch := list(islice(iterator, size)):
        yield batch


def load(path, outpath):
    """Load derivation from path"""
    cmd = nix_cmd("derivation", "show", path)
    drv_infos = parse_nix_derivation_show(
        _exec_required_nix_command(cmd).stdout,
        store_path_hint=path,
    )
    drv_path = path
    drv_info = drv_infos.get(path)
    if drv_info is None and drv_infos:
        drv_path, drv_info = next(iter(drv_infos.items()))
    if drv_info is None:
        raise NixCommandError(
            cmd,
            stderr=f"No derivation metadata returned for '{path}'",
        )
    if outpath is None and path != drv_path and not path.endswith(".drv"):
        outpath = path
    d_obj = Derive.from_nix_derivation_info(drv_path, drv_info, outpath)
    LOG.log(LOG_SPAM, "load derivation: %s", d_obj)
    LOG.log(LOG_SPAM, "derivation attrs: %s", d_obj.to_dict())
    return d_obj


def load_many(paths, output_paths_by_drv=None, batch_size=200, ignore_missing=False):
    """Load many derivations with batched `nix derivation show` calls."""
    if not paths:
        return {}
    output_paths_by_drv = {} if output_paths_by_drv is None else output_paths_by_drv
    loaded = {}
    for batch in _batched(dict.fromkeys(paths), batch_size):
        drv_infos = _load_derivation_infos(
            batch,
            store_path_hint=batch[0],
            ignore_missing=ignore_missing,
        )
        query_to_drv_path = _query_paths_to_derivations(batch, drv_infos)
        output_paths_by_loaded_drv = {}
        missing_paths = []
        for query_path in batch:
            drv_path = query_to_drv_path.get(query_path)
            if drv_path is None:
                missing_paths.append(query_path)
                continue
            output_paths = output_paths_by_loaded_drv.setdefault(drv_path, set())
            output_paths.update(output_paths_by_drv.get(drv_path, ()))
            output_paths.update(output_paths_by_drv.get(query_path, ()))
            if query_path != drv_path and not query_path.endswith(".drv"):
                output_paths.add(query_path)

        for drv_path, output_paths in output_paths_by_loaded_drv.items():
            drv_info = drv_infos[drv_path]
            sorted_output_paths = sorted(output_paths)
            drv = Derive.from_nix_derivation_info(
                drv_path,
                drv_info,
                sorted_output_paths[0] if sorted_output_paths else None,
            )
            for outpath in sorted_output_paths[1:]:
                drv.add_output_path(outpath)
            LOG.log(LOG_SPAM, "load derivation: %s", drv)
            LOG.log(LOG_SPAM, "derivation attrs: %s", drv.to_dict())
            loaded[drv_path] = drv

        for path in missing_paths:
            if ignore_missing:
                LOG.debug("Skipping path without derivation metadata: %s", path)
                continue
            loaded[path] = load(
                path,
                next(iter(output_paths_by_drv.get(path, ())), None),
            )
    return loaded


def _load_derivation_infos(paths, store_path_hint=None, ignore_missing=False):
    if ignore_missing:
        ret = exec_cmd(
            nix_cmd("derivation", "show", *paths),
            raise_on_error=False,
            log_error=False,
        )
    else:
        ret = _exec_required_nix_command(nix_cmd("derivation", "show", *paths))
    if ret is not None:
        return parse_nix_derivation_show(ret.stdout, store_path_hint=store_path_hint)
    if len(paths) == 1:
        return {}
    midpoint = len(paths) // 2
    left = _load_derivation_infos(
        paths[:midpoint],
        store_path_hint=paths[0],
        ignore_missing=ignore_missing,
    )
    right = _load_derivation_infos(
        paths[midpoint:],
        store_path_hint=paths[midpoint],
        ignore_missing=ignore_missing,
    )
    return {**left, **right}


def _query_paths_to_derivations(query_paths, drv_infos):
    output_to_drv_path = {}
    for drv_path, drv_info in drv_infos.items():
        for output_path in _derivation_output_paths(drv_info):
            output_to_drv_path.setdefault(output_path, drv_path)

    query_to_drv_path = {}
    for query_path in query_paths:
        if query_path in drv_infos:
            query_to_drv_path[query_path] = query_path
            continue
        drv_path = output_to_drv_path.get(query_path)
        if drv_path:
            query_to_drv_path[query_path] = drv_path
    return query_to_drv_path


def _derivation_output_paths(drv_info):
    outputs = drv_info.get("outputs", {})
    env_vars = drv_info.get("env", {})
    if not isinstance(outputs, dict):
        outputs = {}
    if not isinstance(env_vars, dict):
        env_vars = {}
    output_paths = []

    def add_output_path(path):
        if path and path not in output_paths:
            output_paths.append(path)

    for output_name, output in outputs.items():
        path = _derivation_output_path(outputs, output_name)
        if path:
            add_output_path(path)
        elif isinstance(output, str):
            add_output_path(output)
        else:
            add_output_path(env_vars.get(output_name))
    for output_name in str(env_vars.get("outputs", "")).split():
        add_output_path(env_vars.get(output_name))
    return output_paths


def load_recursive(path):
    """Load a derivation and its recursive build-time closure."""
    cmd = nix_cmd("derivation", "show", "--recursive", path)
    drv_infos = parse_nix_derivation_show(
        _exec_required_nix_command(cmd).stdout,
        store_path_hint=path,
    )
    if not drv_infos:
        raise NixCommandError(
            cmd,
            stderr=f"No derivation metadata returned for '{path}'",
        )
    loaded = {}
    for drv_path, drv_info in drv_infos.items():
        drv = Derive.from_nix_derivation_info(drv_path, drv_info)
        LOG.log(LOG_SPAM, "load derivation: %s", drv)
        LOG.log(LOG_SPAM, "derivation attrs: %s", drv.to_dict())
        loaded[drv_path] = drv
    return loaded, drv_infos


def _exec_required_nix_command(cmd):
    try:
        return exec_cmd(cmd)
    except subprocess.CalledProcessError as error:
        raise NixCommandError(
            cmd,
            stderr=error.stderr,
            stdout=error.stdout,
        ) from None


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
        if self.store_path is not None:
            raise AssertionError("Derivation is already initialized")
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
