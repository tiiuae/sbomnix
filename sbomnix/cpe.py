# SPDX-FileCopyrightText: 2022 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name, protected-access, too-few-public-methods

""" Generate CPE (Common Platform Enumeration) identifiers"""

import shutil
import logging
import pathlib
import string
import datetime

from sbomnix.utils import (
    LOGGER_NAME,
    LOG_SPAM,
    df_from_csv_file,
    print_df,
    exec_cmd,
)

###############################################################################

_LOG = logging.getLogger(LOGGER_NAME)

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
        _LOG.debug("")
        self.cpedict = pathlib.PosixPath(CACHE_DIR).expanduser() / "cpes.csv"
        self.df_cpedict = self._load_cpedict()

    def _load_cpedict(self):
        _LOG.debug("")
        if not self.cpedict.exists():
            # Try updating cpe dictionary if it's not cached
            if not self._update_cpedict():
                _LOG.warning(
                    "Missing '%s': CPE identifiers will be inaccurate", self.cpedict
                )
                return None
        cpe_updated = datetime.datetime.fromtimestamp(self.cpedict.lstat().st_mtime)
        week_ago = datetime.datetime.now() - datetime.timedelta(days=7)
        if cpe_updated < week_ago:
            # Try updating cpe dictionary if it wasn't recently updated
            if not self._update_cpedict():
                _LOG.warning(
                    "CPE data is not up-to-date: CPE identifiers will be inaccurate"
                )
        return df_from_csv_file(self.cpedict)

    def _update_cpedict(self):
        """Updates cpe dictionary from NVD"""
        _LOG.debug("")
        # Try using update script from 'scripts/update-cpedict.sh'
        update_script = (
            pathlib.Path(__file__).parents[1] / "scripts" / "update-cpedict.sh"
        )
        if update_script.exists():
            self._run_update_script(update_script.as_posix())
            return True
        # Otherwise, if update-cpedict.sh is in PATH, use the installed script
        if shutil.which("update-cpedict.sh"):
            self._run_update_script("update-cpedict.sh")
            return True
        _LOG.debug("update-cpedict.sh not found")
        return False

    def _run_update_script(self, path):
        _LOG.info("Updating CPE dictionary, this might take a moment")
        out = exec_cmd([path, "-f", self.cpedict.as_posix()])
        _LOG.debug("stdout from running '%s':\n%s", path, out)

    def _cpedict_vendor(self, product):
        if not product or len(product) == 1:
            _LOG.debug("invalid product name '%s'", product)
            return None
        if self.df_cpedict is None:
            _LOG.log(LOG_SPAM, "missing cpedict")
            return None
        df = self.df_cpedict[self.df_cpedict["product"] == product]
        if len(df) == 0:
            _LOG.log(LOG_SPAM, "no matches for product '%s'", product)
            return None
        if len(df) != 1:
            # If there are more than one product with the same name,
            # we cannot determine which vendor name should be used for the CPE.
            # Therefore, if more than one product names match, treat it the
            # same way as if there were no matches (returning None).
            if _LOG.level <= LOG_SPAM:
                _LOG.log(LOG_SPAM, "more than one match for product '%s':", product)
                print_df(df)
            return None

        vendor = df["vendor"].values[0]
        _LOG.log(LOG_SPAM, "found vendor for product '%s': '%s'", product, vendor)
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
                _LOG.log(LOG_SPAM, "re-trying with product name '%s'", product_mod)
                vendor = self._cpedict_vendor(product_mod)
        if not vendor:
            # Fallback: use the product name as vendor name
            vendor = product
            _LOG.log(LOG_SPAM, "fallback: use product name as vendor '%s'", vendor)
        return vendor

    def generate(self, name, version):
        """Generate CPE identifier, given the product name and version"""
        cpe_vendor = self._candidate_vendor(name.strip())
        cpe_product = name.strip()
        cpe_version = version.strip()
        cpe_end = "*:*:*:*:*:*:*"
        ret = f"cpe:2.3:a:{cpe_vendor}:{cpe_product}:{cpe_version}:{cpe_end}"
        _LOG.log(LOG_SPAM, "CPE: '%s'", ret)
        return ret


###############################################################################
