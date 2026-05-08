# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared cache path helpers for sbomnix."""

import os
import pathlib
import tempfile
from getpass import getuser


def cache_root():
    """Return the common cache root for sbomnix."""
    candidates = []
    xdg_cache_home = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache_home:
        candidates.append(lambda: pathlib.Path(xdg_cache_home).expanduser() / "sbomnix")
    candidates.append(lambda: pathlib.Path.home() / ".cache" / "sbomnix")
    candidates.append(
        lambda: pathlib.Path(tempfile.gettempdir()) / f"{getuser()}_sbomnix_cache"
    )
    last_error = None
    for get_path in candidates:
        try:
            path = get_path()
            path.mkdir(parents=True, exist_ok=True)
            if not os.access(path, os.W_OK | os.X_OK):
                raise PermissionError(f"Cache root is not writable: {path}")
            return path
        except (OSError, RuntimeError) as error:
            last_error = error
    if last_error is not None:
        raise last_error
    raise RuntimeError("Failed determining sbomnix cache root")


def dfcache_dir():
    """Return the persistent dataframe cache directory."""
    path = cache_root() / "dataframes"
    path.mkdir(parents=True, exist_ok=True)
    return path


def dfcache_lock_path():
    """Return the dataframe cache lock path."""
    return cache_root() / "dataframes.lock"


def meta_lock_path():
    """Return the metadata scan lock path."""
    return cache_root() / "meta.lock"


def http_cache_name():
    """Return the requests-cache base path for persistent HTTP caching."""
    return cache_root() / "http_cache"
