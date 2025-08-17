# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-few-public-methods

"""Cache nixpkgs meta information"""

import os
import re

from common.utils import LOG
from nixmeta.scanner import NixMetaScanner

###############################################################################


class Meta:
    """Cache nixpkgs meta information"""

    def __init__(self):
        LOG.debug("Init")

    def get_nixpkgs_meta(self, nixref=None):
        """
        Return nixpkgs meta pinned in `nixref`. `nixref` can point to a
        nix store path or flake reference. If all else fails, attempt to
        read the nixpkgs store path from NIX_PATH environment variable.
        """
        scanner = NixMetaScanner()
        scanner.scan(nixref)
        df = scanner.to_df()
        # Fallback: try reading nix meta from nixpkgs referenced in NIX_PATH
        if (df is None or df.empty) and "NIX_PATH" in os.environ:
            LOG.debug("Reading nixpkgs path from NIX_PATH environment")
            nix_path = os.environ["NIX_PATH"]
            m_nixpkgs = re.match(r".*nixpkgs=([^:\s]+)", nix_path)
            if m_nixpkgs:
                nixpkgs_path = m_nixpkgs.group(1)
                scanner.scan(nixpkgs_path)
                df = scanner.to_df()
        return df


###############################################################################
