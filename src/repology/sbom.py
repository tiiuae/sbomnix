# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CycloneDX SBOM helpers used by Repology queries."""

import json
import re

import pandas as pd

from common.log import LOG
from common.package_names import nix_to_repology_pkg_name
from common.versioning import parse_version

IGNORE_SBOM_PACKAGE_PATTERNS = (
    r".*\.gz",
    r".*\.patch",
    r".*\.xz",
    r".*\.bz2",
    r".*\.zip",
    r".*\.gem",
    r".*\.tgz",
    r".*\.h",
    r".*\.c",
    r".*\.diff",
    r".*\?.*",
    r".*\&.*",
)
IGNORE_SBOM_REGEX = re.compile(f"(?:{'|'.join(IGNORE_SBOM_PACKAGE_PATTERNS)})")


def parse_cdx_sbom(path):
    """Parse CycloneDX SBOM components into a normalized dataframe."""
    LOG.debug("Parsing cdx sbom: %s", path)
    with open(path, encoding="utf-8") as inf:
        json_dict = json.loads(inf.read())
    metadata = json_dict.get("metadata", {})
    components = list(json_dict.get("components", []))
    if "component" in metadata:
        components.append(metadata["component"])
    components_dict = {}
    for component in components:
        name = nix_to_repology_pkg_name(component["name"])
        components_dict.setdefault("name", []).append(name)
        components_dict.setdefault("version", []).append(component["version"])
    if not components_dict:
        return pd.DataFrame({"name": [], "version": []})
    df_components = pd.DataFrame(components_dict)
    df_components.fillna("", inplace=True)
    df_components = df_components.astype(str)
    df_components.sort_values("name", inplace=True)
    df_components.reset_index(drop=True, inplace=True)
    return df_components


def is_ignored_sbom_package(package_name):
    """Return true if a SBOM component should be ignored for Repology lookup."""
    return re.match(IGNORE_SBOM_REGEX, package_name) is not None


def make_sbom_status_row(repository, package, version, status):
    """Build a synthetic Repology result row for a SBOM component."""
    return {
        "repo": repository,
        "package": package,
        "version": version,
        "status": status,
        "potentially_vulnerable": "",
        "newest_upstream_release": "",
    }


def merge_sbom_fields(df_sbom, df_repo):
    """Join SBOM package/version fields into Repology query results."""
    df = pd.merge(
        left=df_sbom,
        right=df_repo,
        how="left",
        left_on=["name"],
        right_on=["package"],
        suffixes=["_sbom", ""],
    )
    df["version_sbom"] = df.pop("version_sbom")
    df.drop("name", axis=1, inplace=True)
    return df


def sbom_row_classify(row):
    """Classify whether the SBOM version appears outdated."""
    if row.status == "outdated":
        return "sbom_pkg_needs_update"
    if row.status in ["devel", "unique", "newest"]:
        ver_sbom = parse_version(row.version_sbom)
        ver_repo = parse_version(row.version)
        if not ver_sbom or not ver_repo or ver_sbom < ver_repo:
            return "sbom_pkg_needs_update"
    return ""
