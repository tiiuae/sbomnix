# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-few-public-methods

"""Cache nixpkgs meta information"""

import os
import pathlib
import re
import tempfile
from getpass import getuser

from filelock import FileLock

from common.utils import LOG
from nixmeta.scanner import NixMetaScanner, nixref_to_nixpkgs_path
from sbomnix.dfcache import LockedDfCache

###############################################################################

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
        return df

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
