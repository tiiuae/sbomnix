#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the meta.nix graph-walk metadata path (issue #150)."""

import pytest

from common.df import df_from_csv_file
from tests.testpaths import SBOMNIX


@pytest.mark.slow
def test_sbomnix_top_level_package_metadata(_run_python_script, test_work_dir):
    """sbomnix nixpkgs#hello → hello itself has non-empty meta_license_short."""
    out_csv = test_work_dir / "sbom.csv"
    _run_python_script(
        [
            SBOMNIX,
            "nixpkgs#hello",
            "--csv",
            out_csv.as_posix(),
            "--cdx",
            (test_work_dir / "sbom.cdx.json").as_posix(),
            "--spdx",
            (test_work_dir / "sbom.spdx.json").as_posix(),
        ]
    )
    assert out_csv.exists()
    df = df_from_csv_file(out_csv)
    assert df is not None and not df.empty
    hello_rows = df[df["name"].str.startswith("hello-")]
    assert not hello_rows.empty, "no hello row found in SBOM"
    assert hello_rows["meta_license_short"].ne("").any(), (
        "hello has empty meta_license_short — flake-meta path may not be working"
    )


@pytest.mark.slow
def test_sbomnix_haskell_package_metadata(_run_python_script, test_work_dir):
    """sbomnix nixpkgs#haskellPackages.vector → vector and deps have license metadata.

    This is the primary regression test for issue #150: sub-package-set packages
    must get metadata from the dependency-graph walk, not the top-level nix-env scan.
    """
    out_csv = test_work_dir / "sbom.csv"
    _run_python_script(
        [
            SBOMNIX,
            "nixpkgs#haskellPackages.vector",
            "--buildtime",
            "--csv",
            out_csv.as_posix(),
            "--cdx",
            (test_work_dir / "sbom.cdx.json").as_posix(),
            "--spdx",
            (test_work_dir / "sbom.spdx.json").as_posix(),
        ]
    )
    assert out_csv.exists()
    df = df_from_csv_file(out_csv)
    assert df is not None and not df.empty

    names_with_license = set(
        df[df["meta_license_short"].ne("")]["name"]
        .str.replace(r"-\d.*$", "", regex=True)
        .unique()
    )
    for expected in ("vector", "primitive"):
        matches = [n for n in names_with_license if n.startswith(expected)]
        assert matches, (
            f"no '{expected}' package with non-empty meta_license_short found — "
            "sub-package-set metadata (issue #150) may be regressed"
        )


@pytest.mark.slow
def test_sbomnix_flake_meta_cache_hit(_run_python_script, test_work_dir):
    """Running sbomnix twice on the same target gives consistent output."""
    out_csv_1 = test_work_dir / "sbom_1.csv"
    out_csv_2 = test_work_dir / "sbom_2.csv"

    common_args = [
        SBOMNIX,
        "nixpkgs#hello",
        "--cdx",
        (test_work_dir / "sbom.cdx.json").as_posix(),
        "--spdx",
        (test_work_dir / "sbom.spdx.json").as_posix(),
    ]

    _run_python_script([*common_args, "--csv", out_csv_1.as_posix()])
    _run_python_script([*common_args, "--csv", out_csv_2.as_posix()])

    df1 = df_from_csv_file(out_csv_1)
    df2 = df_from_csv_file(out_csv_2)
    assert df1 is not None and df2 is not None
    assert set(df1["name"]) == set(df2["name"]), (
        "second run produced different package names, cache may be corrupting results"
    )
    df1_sorted = df1.sort_values("name").reset_index(drop=True)
    df2_sorted = df2.sort_values("name").reset_index(drop=True)
    for col in ("meta_license_short", "meta_homepage"):
        if col in df1_sorted.columns:
            assert df1_sorted[col].equals(df2_sorted[col]), (
                f"second run produced different {col} values, "
                "cache may be corrupting metadata"
            )
