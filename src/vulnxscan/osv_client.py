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
            setcol(cols.COMPONENT_REF, []).append(package.get(cols.COMPONENT_REF, ""))

    def _parse_batch_response(self, packages, results):
        # Preserve the previous tolerant behavior if the API returns fewer results.
        for package, vulns in zip(packages, results, strict=False):
            if not package or not vulns:
                continue
            LOG.debug("package: %s", package)
            LOG.debug("vulns: %s", vulns)
            if "vulns" not in vulns:
                continue
            self._parse_vulns(package, vulns)

    def _post_batch_query(self, query, packages):
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
        self._parse_batch_response(packages, payload.get("results", []))

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
            setcol(cols.COMPONENT_REF, []).append(component.get("bom-ref", ""))
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
        packages = []
        if ecosystems is None:
            ecosystems = ["GIT", "OSS-Fuzz"]
        for component in df_sbom.to_dict("records"):
            name = component[cols.NAME]
            version = component.get(cols.VERSION, "")
            if not version:
                LOG.debug("skipping osv query (unknown version): %s", name)
                continue
            for ecosystem in ecosystems:
                query = {
                    "version": version,
                    "package": {
                        "name": name,
                        "ecosystem": ecosystem,
                    },
                }
                batchquery["queries"].append(query)
                packages.append(
                    {**query, cols.COMPONENT_REF: component[cols.COMPONENT_REF]}
                )
                if len(batchquery["queries"]) >= max_queries:
                    self._post_batch_query(batchquery, packages)
                    batchquery["queries"] = []
                    packages = []
        if batchquery["queries"]:
            self._post_batch_query(batchquery, packages)

    def to_dataframe(self):
        """Return found vulnerabilities as a pandas dataframe."""
        return pd.DataFrame.from_dict(self.vulns_dict)
