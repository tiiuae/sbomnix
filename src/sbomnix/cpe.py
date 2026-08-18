# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Generate CPE (Common Platform Enumeration) identifiers"""

import io
import string

from requests import RequestException, Session

from common.df import df_from_csv_file, df_log
from common.errors import InvalidCpeDictionaryError
from common.http import mount_retries
from common.log import LOG, LOG_SPAM
from sbomnix.dfcache import LockedDfCache

###############################################################################

_CPE_CSV_URL = "https://github.com/tiiuae/cpedict/raw/main/data/cpes.csv"
# Update local cached version of _CPE_CSV_URL once a day or when local cache
# is cleaned:
_CPE_CSV_CACHE_TTL = 60 * 60 * 24
# Keep cups on its valid cups:cups fallback to avoid Apple's unrelated version
# scale. util-linux has no unambiguous vendor identity to override.
_CPE_OVERRIDES = {
    "brave": ("a", "brave", "browser"),
    "brave-browser": ("a", "brave", "browser"),
    "cairo": ("a", "cairographics", "cairo"),
    "cjson": ("a", "davegamble", "cjson"),
    "curl": ("a", "haxx", "curl"),
    "dhcpcd": ("a", "dhcpcd_project", "dhcpcd"),
    "firefox-bin": ("a", "mozilla", "firefox"),
    "firefox-esr": ("a", "mozilla", "firefox_esr"),
    # Current gawk CVEs use the Fossies CPE identity rather than gnu:gawk.
    "gawk": ("a", "fossies", "gawk"),
    "gcc": ("a", "gnu", "gcc"),
    "glibc": ("a", "gnu", "glibc"),
    "google-chrome": ("a", "google", "chrome"),
    "google-chrome-beta": ("a", "google", "chrome"),
    "google-chrome-dev": ("a", "google", "chrome"),
    "gzip": ("a", "gnu", "gzip"),
    "jq": ("a", "jqlang", "jq"),
    "libcap": ("a", "libcap_project", "libcap"),
    "libsndfile": ("a", "libsndfile_project", "libsndfile"),
    "linux": ("o", "linux", "linux_kernel"),
    "microsoft-edge": ("a", "microsoft", "edge_chromium"),
    "patch": ("a", "gnu", "patch"),
    "python3": ("a", "python", "python"),
    "tor-browser": ("a", "torproject", "tor_browser"),
    "unbound": ("a", "nlnetlabs", "unbound"),
    "unzip": ("a", "unzip_project", "unzip"),
    "wget": ("a", "gnu", "wget"),
    "xdg-utils": ("a", "freedesktop", "xdg-utils"),
    "xwayland": ("a", "x.org", "xwayland"),
}

###############################################################################


class CPE:
    """Generate Common Platform Enumeration identifiers"""

    def __init__(
        self,
        include_cpe=True,
    ):
        self.include_cpe = include_cpe
        self._product_vendor = {}
        self._ambiguous_products = set()
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
            try:
                with mount_retries(Session()) as session:
                    response = session.get(_CPE_CSV_URL, timeout=30)
                    response.raise_for_status()
                    self.df_cpedict = df_from_csv_file(
                        io.StringIO(response.text), exit_on_error=False
                    )
            except RequestException as error:
                LOG.debug("Error downloading cpedict: %s", error)
                self.df_cpedict = None
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
                raise InvalidCpeDictionaryError(required_cols)
            self._init_product_vendor_index()

    def _init_product_vendor_index(self):
        df_cpedict = self.df_cpedict
        if df_cpedict is None:
            return
        product_counts = df_cpedict.groupby("product", sort=False).size()
        unique_products = [
            product for product, count in product_counts.items() if count == 1
        ]
        self._ambiguous_products = {
            product for product, count in product_counts.items() if count != 1
        }
        df_unique = df_cpedict[df_cpedict["product"].isin(unique_products)]
        self._product_vendor = dict(
            zip(df_unique["product"], df_unique["vendor"], strict=False)
        )

    def _cpedict_vendor(self, product):
        if not product or len(product) == 1:
            LOG.debug("invalid product name '%s'", product)
            return None
        if self.df_cpedict is None:
            LOG.log(LOG_SPAM, "missing cpedict")
            return None
        vendor = self._product_vendor.get(product)
        if vendor:
            LOG.log(LOG_SPAM, "found vendor for product '%s': '%s'", product, vendor)
            return vendor
        if product not in self._ambiguous_products:
            LOG.log(LOG_SPAM, "no matches for product '%s'", product)
            return None

        # If there is more than one product with the same name, we cannot
        # determine which vendor name should be used for the CPE. Therefore,
        # treat it the same way as no matches.
        LOG.log(LOG_SPAM, "more than one match for product '%s':", product)
        if LOG.isEnabledFor(LOG_SPAM):
            df = self.df_cpedict[self.df_cpedict["product"] == product]
            df_log(df, LOG_SPAM)
        return None

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
            # Use the product name when no CPE dictionary vendor matches.
            vendor = product
            LOG.log(LOG_SPAM, "using product name as vendor '%s'", vendor)
        return vendor

    def generate(self, name, version):
        """Generate CPE identifier, given the product name and version"""
        if not self.include_cpe:
            LOG.log(LOG_SPAM, "CPE generation disabled")
            return ""
        cpe_product = name.strip()
        cpe_version = version.strip()
        override = _CPE_OVERRIDES.get(cpe_product)
        if override:
            cpe_part, cpe_vendor, cpe_product = override
        else:
            cpe_part = "a"
            cpe_vendor = self._candidate_vendor(cpe_product)
        cpe_end = "*:*:*:*:*:*:*"
        ret = f"cpe:2.3:{cpe_part}:{cpe_vendor}:{cpe_product}:{cpe_version}:{cpe_end}"
        LOG.log(LOG_SPAM, "CPE: '%s'", ret)
        return ret


###############################################################################
