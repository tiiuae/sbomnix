# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-few-public-methods

"""Generate CPE (Common Platform Enumeration) identifiers"""

import string
import sys

from common.utils import LOG, LOG_SPAM, df_from_csv_file, df_log
from sbomnix.dfcache import LockedDfCache

###############################################################################

_CPE_CSV_URL = "https://github.com/tiiuae/cpedict/raw/main/data/cpes.csv"
# Update local cached version of _CPE_CSV_URL once a day or when local cache
# is cleaned:
_CPE_CSV_CACHE_TTL = 60 * 60 * 24

###############################################################################


class CPE:
    """Generate Common Platform Enumeration identifiers"""

    def __init__(
        self,
        include_cpe=True,
    ):
        # Let's initialize the fields anyway.
        if not include_cpe:
            self.df_cpedict = None
            return

        self.cache = LockedDfCache()
        self.df_cpedict = self.cache.get(_CPE_CSV_URL)
        if self.df_cpedict is not None and not self.df_cpedict.empty:
            LOG.debug("read CPE dictionary from cache")
        else:
            LOG.debug("CPE cache miss, downloading: %s", _CPE_CSV_URL)
            self.df_cpedict = df_from_csv_file(_CPE_CSV_URL, exit_on_error=False)
            if self.df_cpedict is None or self.df_cpedict.empty:
                LOG.warning(
                    "Failed downloading cpedict: CPE information might not be accurate"
                )
            else:
                self.cache.set(_CPE_CSV_URL, self.df_cpedict, ttl=_CPE_CSV_CACHE_TTL)

        if self.df_cpedict is not None:
            # Verify the loaded cpedict contains at least the following columns
            required_cols = {"vendor", "product"}
            if not required_cols.issubset(self.df_cpedict):
                LOG.fatal(
                    "Missing required columns %s from cpedict",
                    required_cols,
                )
                sys.exit(1)

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
