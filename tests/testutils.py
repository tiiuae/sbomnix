#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared helper utilities for the test suite."""

import json

import jsonschema
import referencing
import referencing.retrieval
import requests


@referencing.retrieval.to_cached_resource()
def retrieve_schema_via_requests(uri):
    """Retrieve and cache remote JSON schema resources."""
    print(f"retrieving schema: {uri}")
    return requests.get(uri, timeout=10).text


def validate_json(file_path, schema_path):
    """Validate json file matches schema."""
    with (
        open(file_path, encoding="utf-8") as json_file,
        open(schema_path, encoding="utf-8") as schema_file,
    ):
        json_obj = json.load(json_file)
        schema_obj = json.load(schema_file)
        registry = referencing.Registry(retrieve=retrieve_schema_via_requests)
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
