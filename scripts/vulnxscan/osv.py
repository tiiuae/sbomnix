#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=import-error

""" Demonstrate querying OSV db for vulnerabilities based on cdx SBOM """

import argparse
import logging
import os
import sys
import pathlib
import json
import requests
import pandas as pd
from sbomnix.utils import (
    setup_logging,
    LOGGER_NAME,
    LOG_SPAM,
    df_to_csv_file,
)

###############################################################################

_LOG = logging.getLogger(LOGGER_NAME)

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = "Scan CycloneDX SBOM components for OSV vulnerabilities"
    epil = f"Example: ./{os.path.basename(__file__)} /path/to/sbom.json"
    parser = argparse.ArgumentParser(description=desc, epilog=epil)
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)
    helps = "Path to CycloneDX SBOM json file"
    parser.add_argument("SBOM", help=helps, type=pathlib.Path)
    helps = "Path to output file (default: ./osv.csv)"
    parser.add_argument("--out", nargs="?", help=helps, default="osv.csv")
    return parser.parse_args()


################################################################################


class OSV:
    """Query and parse OSV vulnerability data"""

    def __init__(self):
        self.vulns_dict = {}

    def _parse_vulns(self, package, vulns):
        setcol = self.vulns_dict.setdefault
        for vuln in vulns["vulns"]:
            setcol("vuln_id", []).append(vuln["id"])
            setcol("modified", []).append(vuln["modified"])
            setcol("package", []).append(package["package"]["name"])
            setcol("version", []).append(package["version"])

    def _parse_batch_response(self, query, resp):
        for package, vulns in zip(query["queries"], resp["results"]):
            if not package or not vulns:
                continue
            _LOG.debug("package: %s", package)
            _LOG.debug("vulns: %s", vulns)
            self._parse_vulns(package, vulns)

    def _post_batch_query(self, query):
        _LOG.log(LOG_SPAM, "query: %s", query)
        url = "https://api.osv.dev/v1/querybatch"
        _LOG.log(LOG_SPAM, "sending request to '%s'", url)
        resp = requests.post(url, json=query, timeout=30)
        _LOG.debug("resp.status_code: %s", resp.status_code)
        _LOG.log(LOG_SPAM, "resp.json: %s", resp.json())
        resp.raise_for_status()
        self._parse_batch_response(query, resp.json())

    def _parse_sbom(self, path):
        _LOG.debug("Parsing sbom: %s", path)
        with open(path, encoding="utf-8") as inf:
            json_dict = json.loads(inf.read())
            components = json_dict["components"] + [json_dict["metadata"]["component"]]
            components_dict = {}
            setcol = components_dict.setdefault
            for cmp in components:
                setcol("name", []).append(cmp["name"])
                setcol("version", []).append(cmp["version"])
            df_components = pd.DataFrame(components_dict)
            df_components.fillna("", inplace=True)
            df_components = df_components.astype(str)
            df_components.sort_values(
                "name", inplace=True, key=lambda col: col.str.lower()
            )
            df_components.reset_index(drop=True, inplace=True)
            return df_components

    def query_vulns(self, sbom_path):
        """Query each package in sbom for OSV vulnerabilities"""
        _LOG.info("Querying vulnerabilities")
        df_sbom = self._parse_sbom(sbom_path)
        # See the API description at: https://osv.dev/docs/#tag/api.
        # The limit of max 1000 packages per single query is stated in the
        # api documentation at the time of writing.
        max_queries = 1000
        batchquery = {}
        batchquery["queries"] = []
        for drv in df_sbom.itertuples():
            query = {}
            query["version"] = drv.version
            query["package"] = {}
            query["package"]["name"] = drv.name
            batchquery["queries"].append(query)
            if len(batchquery["queries"]) >= max_queries:
                self._post_batch_query(batchquery)
                batchquery["queries"] = []
        if batchquery["queries"]:
            self._post_batch_query(batchquery)

    def to_dataframe(self):
        """Return found vulnerabilities as pandas dataframe"""
        return pd.DataFrame.from_dict(self.vulns_dict)


################################################################################


def main():
    """main entry point"""
    args = getargs()
    setup_logging(args.verbose)
    if not args.SBOM.exists():
        _LOG.fatal("Invalid path: '%s'", args.SBOM)
        sys.exit(1)
    osv = OSV()
    osv.query_vulns(args.SBOM.as_posix())
    df_vulns = osv.to_dataframe()
    df_to_csv_file(df_vulns, args.out)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
