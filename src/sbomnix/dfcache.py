# SPDX-FileCopyrightText: 2022-2024 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Thread-safe DataFrameDiskCache"""

import hashlib
import os
import tempfile

from dfdiskcache import DataFrameDiskCache
from dfdiskcache._core import DiskCacheInfo, get_utcnow_timestamp
from filelock import FileLock
from simplesqlite.query import Set, Where

from sbomnix.cache_paths import dfcache_dir, dfcache_lock_path


class LockedDfCache:
    """Thread-safe (and process-safe) wrapper for DataFrameDiskCache"""

    def __init__(self):
        self.dflock = FileLock(dfcache_lock_path())

    def set(self, key, value, ttl=None):
        """Store dataframe cache entries without cross-device renames."""
        with self.dflock:
            dfcache = DataFrameDiskCache(cache_dir_path=dfcache_dir())
            return _cache_local_set(dfcache, key, value, ttl=ttl)

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


def _cache_local_set(dfcache, key, value, ttl=None):
    """Set dataframe cache entries using a temp file in the cache directory."""
    key_hash = hashlib.sha256(key.strip().encode()).hexdigest()
    cache_fpath = dfcache.cache_dir_path / f"{key_hash}.{dfcache.PICKLE_EXT}"
    tmp_fpath = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            dir=dfcache.cache_dir_path,
            prefix=f"dfdiskcache_{key_hash}_",
            suffix=f".{dfcache.PICKLE_EXT}",
        )
        os.close(fd)
        tmp_fpath = tmp_name
        value.to_pickle(tmp_fpath)
        # df-diskcache writes the temporary file under /tmp and renames it into
        # the cache directory. That fails with EXDEV when those paths are on
        # different filesystems.
        os.replace(tmp_fpath, cache_fpath)
        tmp_fpath = None
    finally:
        if tmp_fpath and os.path.exists(tmp_fpath):
            os.unlink(tmp_fpath)

    utcnow_timestamp = get_utcnow_timestamp()
    where_key = Where(DiskCacheInfo.key, key_hash)
    record_exists = any(DiskCacheInfo.select(where=where_key))

    if not record_exists:
        if ttl is None:
            ttl = dfcache.DEFAULT_TTL

        DiskCacheInfo.insert(
            DiskCacheInfo(
                key=key_hash,
                path=str(cache_fpath),
                ttl=ttl,
                created_at=utcnow_timestamp,
                updated_at=utcnow_timestamp,
            )
        )
    else:
        DiskCacheInfo.update(
            set_query=[
                Set(DiskCacheInfo.path, str(cache_fpath)),
                Set(DiskCacheInfo.updated_at, utcnow_timestamp),
            ],
            where=where_key,
        )

    return key_hash


###############################################################################
