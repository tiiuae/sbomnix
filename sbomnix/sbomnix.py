#!/usr/bin/env python3

""" Python script that generates SBOMs from nix packages """

import argparse
import os
import uuid
import logging
import json

import pandas as pd
import numpy as np
from packageurl import PackageURL

from sbomnix.utils import (
    setup_logging,
    LOGGER_NAME,
    df_to_csv_file,
)

from sbomnix.nix import (
    Store,
)

###############################################################################

_LOG = logging.getLogger(LOGGER_NAME)

###############################################################################


def getargs():
    """Parse command line arguments"""
    desc = (
        "This tool finds all dependencies of the specified nix artifact "
        "in NIX_PATH and "
        "writes SBOM file(s) as specified in output arguments."
    )
    epil = (
        "Example: ./%s /path/to/derivation.drv "
        "--meta /path/to/meta.json --runtime" % os.path.basename(__file__)
    )
    parser = argparse.ArgumentParser(description=desc, epilog=epil)

    helps = "Path to nix artifact, e.g.: derivation file or nix output path"
    parser.add_argument("NIX_PATH", nargs=1, help=helps)

    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)

    helps = "Scan only runtime dependencies (default: false)"
    parser.add_argument("--runtime", help=helps, action="store_true")

    helps = (
        "Path to json file that details meta information. "
        "Generate this file with: `nix-env -qa --meta --json '.*' >meta.json` "
        "then give the path to generated json file to this script via the "
        "--meta argument to include the license and maintainer information "
        "to the output of this script (default: None)"
    )
    parser.add_argument("--meta", nargs="?", help=helps, default=None)

    group = parser.add_argument_group("output arguments")
    helps = "Path to csv output file (default: ./sbom.csv)"
    group.add_argument("--csv", nargs="?", help=helps, default="sbom.csv")
    helps = "Path to cyclonedx output file (default: ./sbom.cdx.json)"
    group.add_argument("--cdx", nargs="?", help=helps, default="sbom.cdx.json")

    return parser.parse_args()


################################################################################


def parse_meta_entry(meta, key):
    """Parse the given key from the metadata entry"""
    if isinstance(meta, dict):
        ret = [meta.get(key, "")]
    elif isinstance(meta, list):
        ret = [x.get(key, "") if isinstance(x, dict) else x for x in meta]
    else:
        ret = [meta]
    return list(filter(None, ret))


def parse_json_metadata(json_filename):
    """Parse package metadata from the specified json file"""

    with open(json_filename, "r") as inf:
        _LOG.info('Loading meta info from "%s"' % json_filename)
        json_dict = json.loads(inf.read())

        dict_selected = {}
        setcol = dict_selected.setdefault
        for nixpkg_name, pkg in json_dict.items():
            # generic package info
            setcol("nixpkgs", []).append(nixpkg_name)
            setcol("name", []).append(pkg.get("name", ""))
            setcol("pname", []).append(pkg.get("pname", ""))
            setcol("version", []).append(pkg.get("version", ""))
            # meta
            meta = pkg.get("meta", {})
            setcol("meta_homepage", []).append(meta.get("homepage", ""))
            setcol("meta_position", []).append(meta.get("position", ""))
            # meta.license
            meta_license = meta.get("license", {})
            license_short = parse_meta_entry(meta_license, key="shortName")
            setcol("meta_license_short", []).append(";".join(license_short))
            license_spdx = parse_meta_entry(meta_license, key="spdxId")
            setcol("meta_license_spdxid", []).append(";".join(license_spdx))
            # meta.maintainers
            meta_maintainers = meta.get("maintainers", {})
            emails = parse_meta_entry(meta_maintainers, key="email")
            setcol("meta_maintainers_email", []).append(";".join(emails))

        return pd.DataFrame(dict_selected)


################################################################################


def licenses_entry_from_row(row, column_name, cdx_license_type):
    """Parse license entries of type cdx_license_type from column_name"""
    licenses = []
    if column_name not in row._asdict():
        # Return empty list if column name is not in row
        return licenses
    license_str = getattr(row, column_name)
    if not license_str:
        # Return empty list if license string is empty
        return licenses
    # Parse the ";" separated licenses to cdx license format
    license_strings = license_str.split(";")
    for license_string in license_strings:
        license = {"license": {cdx_license_type: license_string}}
        licenses.append(license)
    return licenses


def cdx_component_add_licenses(component, row):
    """Add licenses array to cdx component (if any)"""
    licenses = []
    # First, try reading the license in spdxid-format
    # TODO: spdxid license data from meta in many cases is not spdxids
    # but something else, therefore, skipping this for now:
    # licenses = licenses_entry_from_row(row, "meta_license_spdxid", "id")
    # If it fails, try reading the license short name
    if not licenses:
        licenses = licenses_entry_from_row(row, "meta_license_short", "name")
    # Give up if pacakge does not have license information associated
    if not licenses:
        return
    # Otherwise, add the licenses entry
    component["licenses"] = licenses


def df_row_to_cdx_component(row):
    """Convert one entry from df_sbomdb (row) to cdx component"""
    component = {}
    component["type"] = "application"
    component["bom-ref"] = row.store_path
    component["name"] = row.pname
    component["version"] = row.version
    purl = PackageURL(type="nix", name=row.pname, version=row.version)
    component["purl"] = str(purl)
    cdx_component_add_licenses(component, row)
    return component


def sbomdb_to_cdx(df_sbomdb, cdx_path, target_path):
    """Export sbomdb dataframe to cyclonedx json file"""
    # TODO: use a library for this, for instance:
    # https://github.com/CycloneDX/cyclonedx-python-lib

    cdx = {}
    cdx["bomFormat"] = "CycloneDX"
    cdx["specVersion"] = "1.3"
    cdx["version"] = 1
    cdx["serialNumber"] = "urn:uuid:{}".format(uuid.uuid4())
    cdx["metadata"] = {}
    tool = {}
    tool["vendor"] = "Unikie"
    tool["name"] = "sbomnix"
    tool["version"] = "0.1.0"
    cdx["metadata"]["tools"] = []
    cdx["metadata"]["tools"].append(tool)
    cdx["components"] = []
    for row in df_sbomdb.itertuples():
        component = df_row_to_cdx_component(row)
        if row.store_path == target_path:
            cdx["metadata"]["component"] = component
        else:
            cdx["components"].append(component)

    with open(cdx_path, "w") as outfile:
        json_string = json.dumps(cdx, indent=2)
        outfile.write(json_string)
        _LOG.info("Wrote: %s" % outfile.name)


################################################################################


def sbomdb_df(store, meta_json_path=None):
    """Export sbomdb to pandas dataframe"""

    # Convert the store object to dataframe
    df_store = store.to_dataframe()
    df_sbomdb = df_store

    # Add meta information (licenses, maintainers) if file path to
    # meta json was specified
    if meta_json_path is not None:
        df_meta = parse_json_metadata(meta_json_path)
        if logging.root.level <= logging.DEBUG:
            df_to_csv_file(df_meta, "meta.csv")
        # Join based on package name including the version number
        df_sbomdb = df_store.merge(
            df_meta,
            how="left",
            left_on=["name"],
            right_on=["name"],
            suffixes=["", "_meta"],
        )

    df_sbom = df_sbomdb.replace(np.nan, "", regex=True)
    return df_sbom.drop_duplicates(subset="store_path", keep="first")


################################################################################


def main():
    """main entry point"""
    args = getargs()
    setup_logging(args.verbose)
    store = Store(args.NIX_PATH[0], args.runtime)
    target_drv = store.get_target_drv_path()
    if not args.meta:
        _LOG.warning(
            "Command line argument '--meta' missing: SBOM will not include "
            "license information"
        )

    df_sbomdb = sbomdb_df(store, args.meta)

    if args.cdx:
        sbomdb_to_cdx(df_sbomdb, args.cdx, target_drv)
    if args.csv:
        df_to_csv_file(df_sbomdb, args.csv)


################################################################################

if __name__ == "__main__":
    main()

################################################################################
