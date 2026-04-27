#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""CLI integration tests for nixmeta."""

import pytest

from common.df import df_from_csv_file
from tests.testpaths import NIXMETA, REPOROOT


def test_nixmeta_help(_run_python_script):
    """Test nixmeta command line argument: '-h'."""
    _run_python_script([NIXMETA, "-h"])


@pytest.mark.slow
def test_nixmeta_sbomnix_flakeref(_run_python_script, test_work_dir):
    """Test nixmeta with sbomnix flakeref."""
    out_path = test_work_dir / "nixmeta.csv"
    _run_python_script(
        [
            NIXMETA,
            "--out",
            out_path.as_posix(),
            "--flakeref",
            REPOROOT,
        ]
    )
    assert out_path.exists()
    df_meta = df_from_csv_file(out_path)
    assert df_meta is not None
    assert df_meta.shape[0] > 50000
