#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2022 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

""" Tests for sbomnix.py """

import os
import subprocess
import shutil
from pathlib import Path
import json
import jsonschema
import pytest


MYDIR = Path(os.path.dirname(os.path.realpath(__file__)))
TEST_WORK_DIR = MYDIR / "sbomnix_test_data"
TEST_NIX_RESULT = TEST_WORK_DIR / "result"
SBOMNIX = MYDIR / ".." / "sbomnix" / "main.py"


################################################################################


@pytest.fixture(autouse=True)
def set_up_test_data():
    """Fixture to set up the test data"""
    print("setup")
    shutil.rmtree(TEST_WORK_DIR, ignore_errors=True)
    TEST_WORK_DIR.mkdir(parents=True, exist_ok=True)
    # Build nixpkgs.hello, output symlink to TEST_NIX_RESULT
    # (assumes nix-build is available in $PATH)
    cmd = ["nix-build", "<nixpkgs>", "-A", "hello", "-o", TEST_NIX_RESULT]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert Path(TEST_NIX_RESULT).exists()
    os.chdir(TEST_WORK_DIR)
    yield "resource"
    print("clean up")
    shutil.rmtree(TEST_WORK_DIR)


def test_help():
    """
    Test command line argument: '-h'
    """
    cmd = [SBOMNIX, "-h"]
    assert subprocess.run(cmd, check=True).returncode == 0


def test_sbomnix_cdx():
    """
    Test sbomnix generates valid CycloneDX json
    """

    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    cmd = [SBOMNIX, TEST_NIX_RESULT, "--cdx", out_path_cdx.as_posix()]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_cdx.exists()
    schema_path = MYDIR / "resources" / "cdx_bom-1.3.schema.json"
    assert schema_path.exists()
    validate_json(out_path_cdx.as_posix(), schema_path)


def test_sbomnix_cdx_runtime():
    """
    Test sbomnix '--runtime' generates valid CycloneDX json
    """

    out_path_cdx = TEST_WORK_DIR / "sbom_cdx_test.json"
    cmd = [SBOMNIX, TEST_NIX_RESULT, "--cdx", out_path_cdx.as_posix(), "--runtime"]
    assert subprocess.run(cmd, check=True).returncode == 0
    assert out_path_cdx.exists()
    schema_path = MYDIR / "resources" / "cdx_bom-1.3.schema.json"
    assert schema_path.exists()
    validate_json(out_path_cdx.as_posix(), schema_path)


################################################################################


def validate_json(file_path, schema_path):
    """Validate json file matches schema"""
    with open(file_path, encoding="utf-8") as json_file, open(
        schema_path, encoding="utf-8"
    ) as schema_file:
        json_obj = json.load(json_file)
        schema_obj = json.load(schema_file)
        jsonschema.validate(json_obj, schema_obj)


################################################################################


if __name__ == "__main__":
    pytest.main([__file__])


################################################################################
