# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for packaged nixmeta resource files."""

from pathlib import Path


def meta_nix_path() -> Path:
    """Return the packaged ``meta.nix`` helper path."""

    path = Path(__file__).with_name("meta.nix")
    if path.is_file():
        return path
    raise FileNotFoundError(
        "Packaged nixmeta helper is missing: "
        f"'{path}'. Ensure nixmeta/meta.nix is included in the installed package."
    )
