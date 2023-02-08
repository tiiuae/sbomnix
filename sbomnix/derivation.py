# From: https://github.com/flyingcircusio/vulnix/blob/1.10.1/LICENSE:
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Flying Circus Internet Operations GmbH

# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

# pylint: disable=unnecessary-pass, too-many-return-statements
# pylint: disable=invalid-name, eval-used, unidiomatic-typecheck
# pylint: disable=too-many-instance-attributes

""" Nix derivation, originally from https://github.com/flyingcircusio/vulnix """

import functools
import json
import logging
import itertools
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


class SkipDrv(RuntimeError):
    """This derivation cannot be treated as package."""

    pass


def components_lt(left, right):
    """Port from nix/src/libexpr/names.cc"""
    try:
        lnum = int(left)
    except ValueError:
        lnum = None
    try:
        rnum = int(right)
    except ValueError:
        rnum = None
    if lnum is not None and rnum is not None:
        return lnum < rnum
    if left == "" and rnum is not None:
        return True
    if left == "pre" and right != "pre":
        return True
    if right == "pre":
        return False
    if rnum is not None:
        return True
    if lnum is not None:
        return False
    return left < right


def category(char):
    """Classify `char` into: punctuation, digit, non-digit."""
    if char in (".", "-"):
        return 0
    if char in ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"):
        return 1
    return 2


def split_components(v):
    """Yield cohesive groups of digits or non-digits. Skip punctuation."""
    start = 0
    stop = len(v)
    while start < stop:
        cat0 = category(v[start])
        i = start + 1
        while i < stop and category(v[i]) == cat0:
            i += 1
        if cat0 != 0:
            yield v[start:i]
        start = i


def compare_versions(left, right):
    """Compare two versions with the same logic as `nix-env -u`.

    Returns -1 if `left` is older than `right`, 1 if `left` is newer
    than `right`, and 0 if both versions are considered equal.

    See https://nixos.org/nix/manual/#ssec-version-comparisons for rules
    and examples.
    """
    if left == right:
        return 0
    for lc, rc in itertools.zip_longest(
        split_components(left), split_components(right), fillvalue=""
    ):
        if lc == rc:
            continue
        if components_lt(lc, rc):
            return -1
        if components_lt(rc, lc):
            return 1
    return 0


################################################################################


def load(path):
    """Load derivation from path"""
    _LOG.debug("")
    with open(path, encoding="utf-8") as f:
        d_obj = eval(f.read(), {"__builtins__": {}, "Derive": Derive}, {})
    d_obj.store_path = path
    _LOG.debug("load derivation: %s", d_obj)
    if _LOG.level <= LOG_SPAM:
        _LOG.log(LOG_SPAM, "deivation attrs: %s", d_obj.to_dict())
    return d_obj


def destructure(env):
    """Decodes Nix 2.0 __structuredAttrs."""
    return json.loads(env["__json"])


@functools.total_ordering
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

        self.pname = envVars.get("pname", self.name)
        self.version = envVars.get("version", "")
        self.patches = patches or envVars.get("patches", "")
        self.system = envVars.get("system", "")
        self.out = [envVars.get("out", "")]
        self.cpe = CPE().generate(self.pname, self.version)
        self.purl = str(PackageURL(type="nix", name=self.pname, version=self.version))

    def __repr__(self):
        return f"<Derive({repr(self.name)})>"

    def __eq__(self, other):
        if type(self) != type(other):
            return NotImplementedError()
        return self.store_path == other.store_path

    def __hash__(self):
        return hash(self.name)

    def __lt__(self, other):
        if self.pname < other.pname:
            return True
        if self.pname > other.pname:
            return False
        return compare_versions(self.version, other.version) == -1

    def __gt__(self, other):
        if self.pname > other.pname:
            return True
        if self.pname < other.pname:
            return False
        return compare_versions(self.version, other.version) == 1

    def add_outpath(self, path):
        """Add an outpath to derivation"""
        if path not in self.out and path != self.store_path:
            _LOG.debug("adding outpath to %s:%s", self, path)
            bisect.insort(self.out, path)

    def to_dict(self):
        """Return derivation as dictionary"""

        ret = {}
        for attr in vars(self):
            ret[attr] = getattr(self, attr)
        return ret
