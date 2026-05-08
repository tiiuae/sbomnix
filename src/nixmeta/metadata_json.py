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
        return "" if meta is None else str(meta)
    return ";".join(list(filter(None, items)))


def _stringify_meta_scalar(value):
    """Normalize scalar metadata values, preserving empty strings for nulls."""
    return "" if value is None else str(value)


def _normalize_license_entry(entry):
    """Normalize one nixpkgs license entry to a lossless JSON-safe dict."""
    if entry is None:
        return None
    if isinstance(entry, dict):
        if not entry:
            return None
        return {
            "spdxId": entry.get("spdxId"),
            "shortName": entry.get("shortName"),
            "fullName": entry.get("fullName"),
            "raw": entry.get("raw"),
        }
    return {
        "spdxId": None,
        "shortName": None,
        "fullName": None,
        "raw": str(entry),
    }


def _normalize_license_entries(entries):
    """Preserve per-license ordering and raw scalar forms."""
    if entries is None:
        return []
    if isinstance(entries, list):
        normalized = [_normalize_license_entry(entry) for entry in entries]
    else:
        normalized = [_normalize_license_entry(entries)]
    return [entry for entry in normalized if entry is not None]


def _flatten_license_field(entries, key):
    """Keep legacy flattened license columns for compatibility only."""
    return ";".join(
        str(value) for entry in entries if (value := entry.get(key)) not in (None, "")
    )


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
        setcol("meta_ambiguous", []).append(
            _stringify_meta_scalar(pkg.get("ambiguous", False))
        )
        setcol("meta_precise_needed", []).append(
            _stringify_meta_scalar(pkg.get("preciseNeeded", False))
        )
        meta = pkg.get("meta", {})
        setcol("meta_homepage", []).append(parse_meta_entry(meta, key="homepage"))
        setcol("meta_unfree", []).append(_stringify_meta_scalar(meta.get("unfree", "")))
        setcol("meta_description", []).append(
            _stringify_meta_scalar(meta.get("description", ""))
        )
        setcol("meta_position", []).append(
            _stringify_meta_scalar(meta.get("position", ""))
        )
        meta_license = _normalize_license_entries(
            meta.get("licenseEntries", meta.get("license"))
        )
        setcol("meta_license_entries_json", []).append(
            json.dumps(meta_license, sort_keys=True, separators=(",", ":"))
        )
        setcol("meta_license_short", []).append(
            _flatten_license_field(meta_license, "shortName")
        )
        setcol("meta_license_spdxid", []).append(
            _flatten_license_field(meta_license, "spdxId")
        )
        meta_maintainers = meta.get("maintainers", {})
        setcol("meta_maintainers_email", []).append(
            parse_meta_entry(meta_maintainers, key="email")
        )
    return pd.DataFrame(dict_selected).astype(str)
