# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-few-public-methods

"""Cache nixpkgs meta information"""

import os
import re
import logging
import pathlib
import tempfile
from getpass import getuser

import pandas as pd
from filelock import FileLock
from sbomnix.dfcache import LockedDfCache
from nixmeta.scanner import NixMetaScanner, nixref_to_nixpkgs_path
from common.utils import LOG, df_from_csv_file, df_to_csv_file

###############################################################################

_NIXMETA_CSV_URL = "https://github.com/henrirosten/nixmeta/raw/main/data/nixmeta.csv"
# Update local cached version of _NIXMETA_CSV_URL once a day or when local cache
# is cleaned:
_NIXMETA_CSV_URL_TTL = 60 * 60 * 24

# Update locally generated nixpkgs meta-info every 30 days or when local cache
# is cleaned.
_NIXMETA_NIXPKGS_TTL = 60 * 60 * 24 * 30

# FileLock lock path
_FLOCK = pathlib.Path(tempfile.gettempdir()) / f"{getuser()}_sbomnix_meta.lock"

###############################################################################


class Meta:
    """Cache nixpkgs meta information"""

    def __init__(self):
        self.lock = FileLock(_FLOCK)
        self.cache = LockedDfCache()
        # df_nixmeta includes the meta-info from _NIXMETA_CSV_URL
        self.df_nixmeta = self.cache.get(_NIXMETA_CSV_URL)
        if self.df_nixmeta is not None and not self.df_nixmeta.empty:
            LOG.debug("read nixmeta from cache")
        else:
            LOG.debug("nixmeta cache miss, downloading: %s", _NIXMETA_CSV_URL)
            self.df_nixmeta = df_from_csv_file(_NIXMETA_CSV_URL, exit_on_error=False)
            if self.df_nixmeta is None or self.df_nixmeta.empty:
                LOG.warning(
                    "Failed downloading nixmeta: meta information might not be accurate"
                )
            else:
                # Nix meta dictionary stored at _NIXMETA_CSV_URL is
                # regularly updated upstream, we want the local cache
                # to be updated roughly on same schedule (once a day)
                self.cache.set(
                    key=_NIXMETA_CSV_URL,
                    value=self.df_nixmeta,
                    ttl=_NIXMETA_CSV_URL_TTL,
                )

    def get_nixpkgs_meta(self, nixref=None):
        """
        Return nixpkgs meta pinned in `nixref`. `nixref` can point to a
        nix store path or flake reference. If nixref is None, attempt to
        read the nixpkgs store path from NIX_PATH environment variable.
        """
        nixpkgs_path = None
        if nixref:
            # Read meta from nixpkgs pinned by nixref
            LOG.debug("Reading nixpkgs path from nixref: %s", nixref)
            nixpath = nixref_to_nixpkgs_path(nixref)
            if nixpath:
                nixpkgs_path = nixpath.as_posix()
        elif "NIX_PATH" in os.environ:
            # Read meta from nipxkgs referenced in NIX_PATH
            LOG.debug("Reading nixpkgs path from NIX_PATH environment")
            nix_path = os.environ["NIX_PATH"]
            m_nixpkgs = re.match(r"nixpkgs=([^:\s]+)", nix_path)
            if m_nixpkgs:
                nixpkgs_path = m_nixpkgs.group(1)
        df = None
        if nixpkgs_path:
            LOG.debug("Scanning meta-info using nixpkgs path: %s", nixpkgs_path)
            df = self._scan(nixpkgs_path)
        # Supplement the nix meta info from self.df_nixmeta with the
        # meta information extracted either from nixref or NIX_PATH
        df_concat = pd.concat([df, self.df_nixmeta]).astype(str)
        df_concat = df_concat.drop_duplicates().reset_index(drop=True)
        if LOG.level <= logging.DEBUG:
            if df is not None:
                df_to_csv_file(df, "df_nixref.csv")
            if self.df_nixmeta is not None:
                df_to_csv_file(self.df_nixmeta, "df_nixmeta.csv")
            if df_concat is not None:
                df_to_csv_file(df_concat, "df_concat.csv")
        return df_concat

    def _scan(self, nixpkgs_path):
        # In case sbomnix is run concurrently, we want to make sure there's
        # only one instance of NixMetaScanner.scan() running at a time.
        # The reason is, NixMetaScanner.scan() potentially invokes
        # `nix-env -qa --meta --json -f /path/to/nixpkgs` which is very
        # memory intensive. The locking needs to happen here (and not in
        # NixMetaScanner) because this object caches the nixmeta info.
        # First scan generates the cache, after which the consecutive scans
        # will read the scan results from the cache, not having to run
        # the nix-env command again, making the consecutive scans relatively
        # fast and light-weight.
        with self.lock:
            df = self.cache.get(nixpkgs_path)
            if df is not None and not df.empty:
                LOG.debug("found from cache: %s", nixpkgs_path)
                return df
            LOG.debug("cache miss, scanning: %s", nixpkgs_path)
            scanner = NixMetaScanner()
            scanner.scan(nixpkgs_path)
            df = scanner.to_df()
            if df is None or df.empty:
                LOG.warning("Failed scanning nixmeta: %s", nixpkgs_path)
                return None
            # Cache requires some TTL, so we set it to some value here.
            # Although, we could as well store it indefinitely as it should
            # not change given the same key (nixpkgs store path).
            self.cache.set(key=nixpkgs_path, value=df, ttl=_NIXMETA_NIXPKGS_TTL)
            return df


###############################################################################
