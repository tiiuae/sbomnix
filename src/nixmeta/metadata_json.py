# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for flattening nix-env metadata JSON."""

import json

import pandas as pd

from common import columns as cols
from common.log import LOG


def parse_meta_entry(meta, key):
    """Flatten nested metadata values for a single key into a string."""
    items = []
    if isinstance(meta, dict):
        items.extend([parse_meta_entry(meta.get(key, ""), key)])
    elif isinstance(meta, list):
        items.extend([parse_meta_entry(item, key) for item in meta])
    else:
        return str(meta)
    return ";".join(list(filter(None, items)))


def parse_json_metadata(json_filename, *, log=LOG):
    """Parse package metadata from a ``nix-env --json`` output file."""
    with open(json_filename, "r", encoding="utf-8") as inf:
        log.debug('Loading meta-info from "%s"', json_filename)
        json_dict = json.loads(inf.read())
    dict_selected = {}
    setcol = dict_selected.setdefault
    for pkg in json_dict.values():
        setcol(cols.NAME, []).append(pkg.get("name", ""))
        setcol("pname", []).append(pkg.get("pname", ""))
        setcol(cols.VERSION, []).append(pkg.get("version", ""))
        meta = pkg.get("meta", {})
        setcol("meta_homepage", []).append(parse_meta_entry(meta, key="homepage"))
        setcol("meta_unfree", []).append(meta.get("unfree", ""))
        setcol("meta_description", []).append(meta.get("description", ""))
        setcol("meta_position", []).append(meta.get("position", ""))
        meta_license = meta.get("license", {})
        setcol("meta_license_short", []).append(
            parse_meta_entry(meta_license, key="shortName")
        )
        setcol("meta_license_spdxid", []).append(
            parse_meta_entry(meta_license, key="spdxId")
        )
        meta_maintainers = meta.get("maintainers", {})
        setcol("meta_maintainers_email", []).append(
            parse_meta_entry(meta_maintainers, key="email")
        )
    return pd.DataFrame(dict_selected).astype(str)
