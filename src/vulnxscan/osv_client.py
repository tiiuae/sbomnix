# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Reusable OSV querying helpers."""

import json

import pandas as pd

from common import columns as cols
from common.http import create_cached_limited_session
from common.log import LOG, LOG_SPAM

OSV_CACHE_SECONDS = 6 * 60 * 60
OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
OSV_REQUEST_TIMEOUT = 60
OSV_USER_AGENT = "sbomnix-osv/0 (https://github.com/tiiuae/sbomnix/)"


def create_osv_session():
    """Return a retrying HTTP session for OSV requests."""
    return create_cached_limited_session(
        per_second=1,
        expire_after=OSV_CACHE_SECONDS,
        user_agent=OSV_USER_AGENT,
        allowed_methods=frozenset(("GET", "HEAD", "POST")),
    )


class OSV:
    """Query and parse OSV vulnerability data."""

    def __init__(self, session=None, request_timeout=OSV_REQUEST_TIMEOUT):
        self.session = create_osv_session() if session is None else session
        self.request_timeout = request_timeout
        self.vulns_dict = {}

    def _parse_vulns(self, package, vulns):
        setcol = self.vulns_dict.setdefault
        for vuln in vulns["vulns"]:
            setcol(cols.VULN_ID, []).append(vuln["id"])
            setcol(cols.MODIFIED, []).append(vuln["modified"])
            setcol(cols.PACKAGE, []).append(package["package"]["name"])
            setcol(cols.VERSION, []).append(package["version"])

    def _parse_batch_response(self, query, results):
        for package, vulns in zip(query["queries"], results, strict=False):
            if not package or not vulns:
                continue
            LOG.debug("package: %s", package)
            LOG.debug("vulns: %s", vulns)
            if "vulns" not in vulns:
                continue
            self._parse_vulns(package, vulns)

    def _post_batch_query(self, query):
        LOG.log(LOG_SPAM, "query: %s", query)
        LOG.log(LOG_SPAM, "sending request to '%s'", OSV_QUERY_URL)
        resp = self.session.post(
            OSV_QUERY_URL,
            json=query,
            timeout=self.request_timeout,
        )
        LOG.debug("resp.status_code: %s", resp.status_code)
        LOG.log(LOG_SPAM, "resp.json: %s", resp.json())
        resp.raise_for_status()
        payload = resp.json()
        self._parse_batch_response(query, payload.get("results", []))

    def _parse_sbom(self, path):
        LOG.debug("Parsing sbom: %s", path)
        with open(path, encoding="utf-8") as inf:
            json_dict = json.loads(inf.read())
        components = json_dict["components"] + [json_dict["metadata"]["component"]]
        components_dict = {}
        setcol = components_dict.setdefault
        for component in components:
            setcol(cols.NAME, []).append(component["name"])
            setcol(cols.VERSION, []).append(component["version"])
        df_components = pd.DataFrame(components_dict)
        df_components.fillna("", inplace=True)
        df_components = df_components.astype(str)
        df_components.sort_values(
            cols.NAME,
            inplace=True,
            key=lambda col: col.str.lower(),
        )
        df_components.reset_index(drop=True, inplace=True)
        return df_components

    def query_vulns(self, sbom_path, ecosystems=None):
        """Query each package in an SBOM for OSV vulnerabilities."""
        LOG.verbose("Querying vulnerabilities")
        df_sbom = self._parse_sbom(sbom_path)
        max_queries = 1000
        batchquery = {"queries": []}
        if ecosystems is None:
            ecosystems = ["GIT", "OSS-Fuzz"]
        for drv in df_sbom.itertuples():
            if not drv.version:
                LOG.debug("skipping osv query (unknown version): %s", drv.name)
                continue
            for ecosystem in ecosystems:
                query = {
                    "version": drv.version,
                    "package": {
                        "name": drv.name,
                        "ecosystem": ecosystem,
                    },
                }
                batchquery["queries"].append(query)
                if len(batchquery["queries"]) >= max_queries:
                    self._post_batch_query(batchquery)
                    batchquery["queries"] = []
        if batchquery["queries"]:
            self._post_batch_query(batchquery)

    def to_dataframe(self):
        """Return found vulnerabilities as a pandas dataframe."""
        return pd.DataFrame.from_dict(self.vulns_dict)
