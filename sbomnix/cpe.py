# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name, protected-access, too-few-public-methods

""" Generate CPE (Common Platform Enumeration) identifiers"""

import sys
import pathlib
import string
import datetime
import shutil
import requests

from sbomnix.utils import (
    LOG,
    LOG_SPAM,
    df_from_csv_file,
    df_log,
)

###############################################################################

CACHE_DIR = "~/.cache/sbomnix"

###############################################################################


def CPE():
    """Return CPE instance"""
    if _CPE._instance is None:
        _CPE._instance = _CPE()
    return _CPE._instance


class _CPE:
    """Generate Common Platform Enumeration identifiers"""

    _instance = None

    def __init__(self):
        LOG.debug("")
        self.cpedict = pathlib.PosixPath(CACHE_DIR).expanduser() / "cpes.csv"
        self.cpedict.parent.mkdir(parents=True, exist_ok=True)
        self.df_cpedict = self._load_cpedict()
        if self.df_cpedict is not None:
            # Verify the loaded cpedict contains at least the following columns
            required_cols = {"vendor", "product"}
            if not required_cols.issubset(self.df_cpedict):
                LOG.fatal(
                    "Missing required columns %s from cpedict, manually check: '%s'",
                    required_cols,
                    self.cpedict,
                )
                sys.exit(1)

    def _load_cpedict(self):
        LOG.debug("")
        if not self.cpedict.exists() or self.cpedict.stat().st_size <= 0:
            # Try updating cpe dictionary if it's not cached
            if not self._update_cpedict():
                LOG.warning(
                    "Missing '%s': CPE identifiers will be inaccurate", self.cpedict
                )
                return None
        cpe_updated = datetime.datetime.fromtimestamp(self.cpedict.lstat().st_mtime)
        week_ago = datetime.datetime.now() - datetime.timedelta(days=7)
        if cpe_updated < week_ago:
            # Try updating cpe dictionary if it wasn't recently updated
            LOG.debug("Attempting periodic update of cpe dictionary")
            if not self._update_cpedict():
                LOG.warning(
                    "CPE data is not up-to-date: CPE identifiers will be inaccurate"
                )
        return df_from_csv_file(self.cpedict)

    def _update_cpedict(self):
        """Updates local cpe dictionary"""
        LOG.debug("")
        cpedict_bak = None
        if self.cpedict.exists() and self.cpedict.stat().st_size > 0:
            # Backup the original cpedict to be able to rollback in case the update
            # fails
            cpedict_bak = pathlib.PosixPath(CACHE_DIR).expanduser() / "cpes.csv.bak"
            shutil.copy(self.cpedict, cpedict_bak)
        with open(self.cpedict.as_posix(), "wb") as f:
            url = "https://github.com/tiiuae/cpedict/raw/main/data/cpes.csv"
            try:
                f.write(requests.get(url, stream=True, timeout=10).content)
                return True
            except requests.exceptions.RequestException as e:
                LOG.warning("CPE data update failed: %s", e)
                if cpedict_bak:
                    LOG.debug("Rollback earlier cpedict after failed update")
                    shutil.copy(cpedict_bak, self.cpedict)
                return False

    def _cpedict_vendor(self, product):
        if not product or len(product) == 1:
            LOG.debug("invalid product name '%s'", product)
            return None
        if self.df_cpedict is None:
            LOG.log(LOG_SPAM, "missing cpedict")
            return None
        df = self.df_cpedict[self.df_cpedict["product"] == product]
        if len(df) == 0:
            LOG.log(LOG_SPAM, "no matches for product '%s'", product)
            return None
        if len(df) != 1:
            # If there is more than one product with the same name,
            # we cannot determine which vendor name should be used for the CPE.
            # Therefore, if more than one product names match, treat it the
            # same way as if there were no matches (returning None).
            LOG.log(LOG_SPAM, "more than one match for product '%s':", product)
            df_log(df, LOG_SPAM)
            return None

        vendor = df["vendor"].values[0]
        LOG.log(LOG_SPAM, "found vendor for product '%s': '%s'", product, vendor)
        return vendor

    def _candidate_vendor(self, product):
        """
        Return vendor name based on the product name:
            - Try finding exact match from the CPE dictionary
            - Try finding exact match based on variations of the product name
            - Use product name as vendor name if other attempts failed
        """
        vendor = self._cpedict_vendor(product)
        if not vendor:
            # No exact match found from cpe dictionary based on product name:
            # try finding vendor for the product name we get by removing
            # possible trailing digits from the original product name
            product_mod = product.rstrip(string.digits)
            if product != product_mod:
                LOG.log(LOG_SPAM, "re-trying with product name '%s'", product_mod)
                vendor = self._cpedict_vendor(product_mod)
        if not vendor:
            # Fallback: use the product name as vendor name
            vendor = product
            LOG.log(LOG_SPAM, "fallback: use product name as vendor '%s'", vendor)
        return vendor

    def generate(self, name, version):
        """Generate CPE identifier, given the product name and version"""
        cpe_vendor = self._candidate_vendor(name.strip())
        cpe_product = name.strip()
        cpe_version = version.strip()
        cpe_end = "*:*:*:*:*:*:*"
        ret = f"cpe:2.3:a:{cpe_vendor}:{cpe_product}:{cpe_version}:{cpe_end}"
        LOG.log(LOG_SPAM, "CPE: '%s'", ret)
        return ret


###############################################################################
