# SPDX-FileCopyrightText: 2022-2024 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Thread-safe DataFrameDiskCache"""

from dfdiskcache import DataFrameDiskCache
from filelock import FileLock

from sbomnix.cache_paths import dfcache_dir, dfcache_lock_path


class LockedDfCache:
    """Thread-safe (and process-safe) wrapper for DataFrameDiskCache"""

    def __init__(self):
        self.dflock = FileLock(dfcache_lock_path())

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
                dfcache = DataFrameDiskCache(cache_dir_path=dfcache_dir())
                return getattr(dfcache, name)(*a, **k)

        return wrap


###############################################################################
