#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

"""Unit tests for typed library exceptions."""

import subprocess
from types import SimpleNamespace

import pandas as pd
import pytest

from common import df as common_df
from common import proc as common_proc
from common.errors import (
    CommandNotFoundError,
    CsvLoadError,
    InvalidCpeDictionaryError,
    InvalidNixArtifactError,
    MissingNixDeriverError,
    MissingNixOutPathError,
    WhitelistApplicationError,
)
from nixgraph import graph as nixgraph_graph
from repology import repology_cve
from sbomnix import cpe
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
        common_proc.exit_unless_command_exists("nix", which_fn=lambda _name: None)


def test_exit_unless_nix_artifact_raises_typed_error(monkeypatch):
    def fail_exec_cmd(*_args, **_kwargs):
        raise subprocess.CalledProcessError(1, ["nix-store", "-q", "missing"])

    with pytest.raises(
        InvalidNixArtifactError,
        match="Specified target is not a nix artifact: 'missing'",
    ):
        common_proc.exit_unless_nix_artifact("missing", exec_cmd_fn=fail_exec_cmd)


def test_find_deriver_raises_typed_error(monkeypatch):
    monkeypatch.setattr(nixgraph_graph, "find_deriver", lambda _path: None)

    with pytest.raises(MissingNixDeriverError, match="No deriver found for: 'missing'"):
        nixgraph_graph._find_deriver("missing")


def test_find_outpath_raises_typed_error(monkeypatch):
    monkeypatch.setattr(
        nixgraph_graph, "exec_cmd", lambda *_args, **_kwargs: SimpleNamespace(stdout="")
    )

    with pytest.raises(
        MissingNixOutPathError, match="No outpath found for: 'missing.drv'"
    ):
        nixgraph_graph._find_outpath("missing.drv")


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
    assert repology_cve._report(None) is False
    assert repology_cve._report(pd.DataFrame()) is False
