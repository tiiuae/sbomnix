#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for typed library exceptions."""

import subprocess

import pandas as pd
import pytest

from common import df as common_df
from common.errors import (
    CommandNotFoundError,
    CsvLoadError,
    InvalidCpeDictionaryError,
    InvalidNixArtifactError,
    InvalidNixJsonError,
    MissingNixDeriverError,
    WhitelistApplicationError,
)
from common.proc import exit_unless_command_exists, exit_unless_nix_artifact
from repology.reporting import report_cves
from sbomnix import cpe
from sbomnix.derivers import require_deriver
from vulnxscan import whitelist


def test_df_from_csv_file_raises_csv_load_error(monkeypatch):
    def fail_read_csv(*_args, **_kwargs):
        raise pd.errors.ParserError("bad csv")

    monkeypatch.setattr(common_df.pd, "read_csv", fail_read_csv)

    with pytest.raises(CsvLoadError, match="Error reading csv file 'broken.csv'"):
        common_df.df_from_csv_file("broken.csv")


def test_df_log_ignores_none():
    common_df.df_log(None, 0)


def test_exit_unless_command_exists_raises_typed_error():
    with pytest.raises(CommandNotFoundError, match="command 'nix' is not in PATH"):
        exit_unless_command_exists("nix", which_fn=lambda _name: None)


def test_exit_unless_nix_artifact_raises_typed_error():
    def fail_exec_cmd(*_args, **_kwargs):
        raise subprocess.CalledProcessError(1, ["nix-store", "-q", "missing"])

    with pytest.raises(
        InvalidNixArtifactError,
        match="Specified target is not a nix artifact: 'missing'",
    ):
        exit_unless_nix_artifact("missing", exec_cmd_fn=fail_exec_cmd)


def test_find_deriver_raises_typed_error():
    with pytest.raises(MissingNixDeriverError, match="No deriver found for: 'missing'"):
        require_deriver("missing", find_deriver_fn=lambda _path: None)


def test_require_deriver_wraps_lookup_runtime_errors():
    def fail_find_deriver(_path):
        raise RuntimeError("deriver metadata exists but is not loadable")

    with pytest.raises(
        MissingNixDeriverError,
        match="No deriver found for: 'missing'",
    ):
        require_deriver("missing", find_deriver_fn=fail_find_deriver)


def test_require_deriver_preserves_typed_lookup_errors():
    def fail_find_deriver(_path):
        raise InvalidNixJsonError("nix derivation show", "bad schema")

    with pytest.raises(InvalidNixJsonError, match="bad schema"):
        require_deriver("missing", find_deriver_fn=fail_find_deriver)


def test_cpe_raises_typed_error_when_required_columns_are_missing(monkeypatch):
    class FakeCache:
        def get(self, _url):
            return pd.DataFrame({"product": ["openssl"]})

        def set(self, *_args, **_kwargs):
            raise AssertionError("cache set should not be called for populated data")

    monkeypatch.setattr(cpe, "LockedDfCache", FakeCache)

    with pytest.raises(InvalidCpeDictionaryError, match="cpedict"):
        cpe.CPE()


def test_df_apply_whitelist_raises_typed_error_without_vuln_id_column():
    df_whitelist = pd.DataFrame({"vuln_id": ["CVE-.*"], "comment": ["reason"]})
    df_vulns = pd.DataFrame({"package": ["openssl"]})

    with pytest.raises(
        WhitelistApplicationError,
        match="Missing 'vuln_id' column from df_vulns",
    ):
        whitelist.df_apply_whitelist(df_whitelist, df_vulns)


def test_repology_cve_report_returns_false_on_empty_results():
    assert report_cves(None) is False
    assert report_cves(pd.DataFrame()) is False
