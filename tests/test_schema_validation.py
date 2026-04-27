#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for offline schema validation helpers."""

from tests.testpaths import RESOURCES_DIR, SAMPLE_CDX_SBOM
from tests.testutils import resolve_local_schema_path, validate_json


def test_local_schema_aliases_resolve_to_vendored_resources():
    """Resolve the vendored schema aliases used by local validation."""
    assert resolve_local_schema_path("spdx.schema.json", RESOURCES_DIR).name == (
        "spdx.schema.json"
    )
    assert (
        resolve_local_schema_path(
            "http://cyclonedx.org/schema/spdx.schema.json",
            RESOURCES_DIR,
        ).name
        == "spdx.schema.json"
    )
    assert (
        resolve_local_schema_path(
            "jsf-0.82.schema.json#/definitions/signature",
            RESOURCES_DIR,
        ).name
        == "jsf-0.82.schema.json"
    )


def test_validate_json_uses_only_local_schema_resources():
    """Validate a sample CycloneDX SBOM without network access."""
    validate_json(SAMPLE_CDX_SBOM, RESOURCES_DIR / "cdx_bom-1.4.schema.json")
