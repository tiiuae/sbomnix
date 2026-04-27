# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Package name normalization helpers."""

import re

import pandas as pd


def nix_to_repology_pkg_name(nix_pkg_name):
    """Convert nix package name to repology package name."""
    if not nix_pkg_name or pd.isnull(nix_pkg_name):
        return nix_pkg_name
    nix_pkg_name = nix_pkg_name.lower()
    re_nix_to_repo = re.compile(
        r"^(?:"
        r"(python)|(perl)|(emacs)|(vim)plugin|(ocaml)|"
        r"(gnome)-shell-extension|(lisp)|(ruby)|(lua)|"
        r"(php)[0-9]*Packages|(go)|(coq)|(rust)"
        r")"
        r"[0-9.]*-(.+)"
    )
    match = re.match(re_nix_to_repo, nix_pkg_name)
    if match:
        matches = list(filter(None, match.groups()))
        assert len(matches) == 2, f"Unexpected package name '{nix_pkg_name}'"
        nix_pkg_name = f"{matches[0]}:{matches[1]}"
    if nix_pkg_name == "python3":
        nix_pkg_name = "python"
    if nix_pkg_name == "libtiff":
        nix_pkg_name = "tiff"
    return nix_pkg_name
