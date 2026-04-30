# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Package metadata helpers."""

import importlib.metadata
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


def get_py_pkg_version(package="sbomnix"):
    """Return package version, including git state when run from source."""
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return _dev_version()


def _dev_version():
    """Derive version from git when the package is not installed.

    Produces the same format as the Nix package version so that devshell
    and nix-built invocations report identical strings for the same checkout:
      <base>+g<hash>          clean tree with commits beyond the release tag
      <base>+g<hash>.dirty    tree has tracked modifications (untracked files ignored)
    pip normalises '-' to '.' in local version identifiers, so '.dirty' is
    used here to match what importlib.metadata returns from the installed
    package.
    """
    try:
        base = (_REPO_ROOT / "VERSION").read_text().strip()
        short_hash = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=_REPO_ROOT,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            check=True,
            cwd=_REPO_ROOT,
        ).stdout.strip()
        return f"{base}+g{short_hash}{'.dirty' if dirty else ''}"
    except Exception:
        try:
            return (_REPO_ROOT / "VERSION").read_text().strip() + ".dev"
        except Exception:
            return "0.0.0"
