#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CLI integration tests for provenance."""

from tests.testpaths import PROVENANCE, RESOURCES_DIR
from tests.testutils import validate_json


def test_provenance_help(_run_python_script):
    """Test provenance command line argument: '-h'."""
    _run_python_script([PROVENANCE, "-h"])


def test_provenance_schema(_run_python_script, test_nix_drv, test_work_dir):
    """Test provenance generates valid schema."""
    out_path = test_work_dir / "provenance_test.json"
    _run_python_script(
        [
            PROVENANCE,
            test_nix_drv,
            "--out",
            out_path.as_posix(),
        ]
    )
    assert out_path.exists()
    schema_path = RESOURCES_DIR / "provenance-1.0.schema.json"
    assert schema_path.exists()
    validate_json(out_path.as_posix(), schema_path)


def test_provenance_schema_recursive(_run_python_script, test_nix_drv, test_work_dir):
    """Test provenance generates valid schema with recursive option."""
    out_path = test_work_dir / "recursive_provenance_test.json"
    _run_python_script(
        [
            PROVENANCE,
            test_nix_drv,
            "--recursive",
            "--out",
            out_path.as_posix(),
        ]
    )
    assert out_path.exists()
    schema_path = RESOURCES_DIR / "provenance-1.0.schema.json"
    assert schema_path.exists()
    validate_json(out_path.as_posix(), schema_path)
