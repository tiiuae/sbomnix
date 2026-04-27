#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared helper utilities for the test suite."""

import json
from pathlib import Path
from urllib.parse import urldefrag, urlparse

import jsonschema
import referencing
import referencing.retrieval

LOCAL_SCHEMA_ALIASES = {
    "spdx.schema.json": "spdx.schema.json",
    "http://cyclonedx.org/schema/spdx.schema.json": "spdx.schema.json",
    "jsf-0.82.schema.json": "jsf-0.82.schema.json",
    "http://cyclonedx.org/schema/jsf-0.82.schema.json": "jsf-0.82.schema.json",
}


def resolve_local_schema_path(uri, schema_dir):
    """Resolve a schema reference to a local file under ``schema_dir``."""
    schema_dir = Path(schema_dir)
    base_uri, _fragment = urldefrag(uri)
    if base_uri in LOCAL_SCHEMA_ALIASES:
        filename = LOCAL_SCHEMA_ALIASES[base_uri]
    else:
        parsed = urlparse(base_uri)
        filename = Path(parsed.path or base_uri).name
        filename = LOCAL_SCHEMA_ALIASES.get(filename, filename)
    path = schema_dir / filename
    if not path.exists():
        raise FileNotFoundError(f"Local schema not found for '{uri}': {path}")
    return path


def create_local_schema_retriever(schema_dir):
    """Create a cached local schema retriever for ``referencing``."""

    @referencing.retrieval.to_cached_resource()
    def _retrieve(uri):
        return resolve_local_schema_path(uri, schema_dir).read_text(encoding="utf-8")

    return _retrieve


def validate_json(file_path, schema_path):
    """Validate json file matches schema."""
    schema_path = Path(schema_path)
    with (
        open(file_path, encoding="utf-8") as json_file,
        open(
            schema_path,
            encoding="utf-8",
        ) as schema_file,
    ):
        json_obj = json.load(json_file)
        schema_obj = json.load(schema_file)
        registry = referencing.Registry(
            retrieve=create_local_schema_retriever(schema_path.parent)
        )
        jsonschema.validate(json_obj, schema_obj, registry=registry)


def df_to_string(df):
    """Convert dataframe to string."""
    return (
        "\n"
        + df.to_string(max_rows=None, max_cols=None, index=False, justify="left")
        + "\n"
    )


def df_difference(df_left, df_right):
    """Return dataframe that represents diff of two dataframes."""
    df_right = df_right.astype(df_left.dtypes.to_dict())
    df = df_left.merge(
        df_right,
        how="outer",
        indicator=True,
    )
    df = df[df["_merge"] != "both"]
    cols = df.columns.tolist()
    cols = cols[-1:] + cols[:-1]
    return df[cols]
