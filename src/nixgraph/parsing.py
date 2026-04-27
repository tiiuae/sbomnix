#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for parsing nix dependency graph output."""

import re
from dataclasses import dataclass

DEPENDENCY_RE = re.compile(
    r"^\"(?P<src_hash>[^-]+)-(?P<src_pname>.*?)"
    r"\" -> \""
    r"(?P<target_hash>[^-]+)-(?P<target_pname>.*?)\""
)


@dataclass(eq=False)
class NixDependency:
    """Represents dependency between two nix packages."""

    src_path: str
    src_pname: str
    target_path: str
    target_pname: str

    def to_dict(self):
        """Return as dictionary."""
        return {attr: getattr(self, attr) for attr in vars(self)}


def dependency_from_match(dep_match, nix_store_path):
    """Build a dependency record from a nix-store graph regex match."""
    src_pname = dep_match.group("src_pname")
    src_hash = dep_match.group("src_hash")
    src_path = f"{nix_store_path}{src_hash}-{src_pname}"
    target_pname = dep_match.group("target_pname")
    target_hash = dep_match.group("target_hash")
    target_path = f"{nix_store_path}{target_hash}-{target_pname}"
    return NixDependency(src_path, src_pname, target_path, target_pname)


def parse_nix_query_out(nix_query_out, nix_store_path):
    """Parse ``nix-store --graph`` output into dependency edges."""
    dependencies = set()
    for line in nix_query_out.splitlines():
        dep_match = DEPENDENCY_RE.match(line)
        if dep_match:
            dependencies.add(dependency_from_match(dep_match, nix_store_path))
    return dependencies
