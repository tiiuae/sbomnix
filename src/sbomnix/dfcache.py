# SPDX-FileCopyrightText: 2022-2024 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-few-public-methods

"""Thread-safe DataFrameDiskCache"""

import pathlib
import tempfile
from getpass import getuser

from dfdiskcache import DataFrameDiskCache
from filelock import FileLock

###############################################################################

# DataFrameDiskCache cache local path and lock file
DFCACHE_PATH = pathlib.Path(tempfile.gettempdir()) / f"{getuser()}_sbomnix_df_cache"
DFCACHE_LOCK = DFCACHE_PATH / "dfcache.lock"

################################################################################


class LockedDfCache:
    """Thread-safe (and process-safe) wrapper for DataFrameDiskCache"""

    def __init__(self):
        self.dflock = FileLock(DFCACHE_LOCK)

    def __getattr__(self, name):
        def wrap(*a, **k):
            with self.dflock:
                # We intentionally do not store the dfcache as object variable
                # but re-instantiate it every time any LockedDfCache method
                # is called. DataFrameDiskCache internally makes use of sqlite
                # which does not allow concurrent connections to the database.
                # Having the dfcache initiated once in __init__() and then
                # re-used here would mean the connection would remain reserved
                # for the first thread making other threads throw with
                # 'database locked' etc. even if we otherwise protect
                # concurrent writes.
                dfcache = DataFrameDiskCache(cache_dir_path=DFCACHE_PATH)
                return getattr(dfcache, name)(*a, **k)

        return wrap


###############################################################################
