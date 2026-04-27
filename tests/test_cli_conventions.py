#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=missing-function-docstring,protected-access

"""Focused tests for shared CLI conventions."""

from pathlib import Path

import pytest

from common.pkgmeta import get_py_pkg_version
from nixgraph import main as nixgraph_main
from nixmeta import main as nixmeta_main
from nixupdate import nix_outdated
from provenance import main as provenance_main
from repology import repology_cli, repology_cve
from sbomnix import main as sbomnix_main
from vulnxscan import osv as osv_cli
from vulnxscan import vulnxscan_cli


def _stringify(value):
    if isinstance(value, Path):
        return value.as_posix()
    return str(value)


@pytest.mark.parametrize(
    "getargs",
    [
        sbomnix_main.getargs,
        nixgraph_main.getargs,
        nixmeta_main._getargs,
        nix_outdated.getargs,
        vulnxscan_cli.getargs,
        osv_cli.getargs,
        repology_cli.getargs,
        repology_cve.getargs,
        provenance_main.getargs,
    ],
)
def test_cli_version_flags_exit_zero(getargs, capsys):
    with pytest.raises(SystemExit) as excinfo:
        getargs(["--version"])

    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == get_py_pkg_version()


@pytest.mark.parametrize(
    ("getargs", "argv"),
    [
        (sbomnix_main.getargs, ["-v", "2", ".#pkg"]),
        (nixgraph_main.getargs, ["-v", "2", ".#pkg"]),
        (nixmeta_main._getargs, ["-v", "2"]),
        (nix_outdated.getargs, ["-v", "2", ".#pkg"]),
        (vulnxscan_cli.getargs, ["-v", "2", ".#pkg"]),
        (osv_cli.getargs, ["-v", "2", "sbom.json"]),
        (
            repology_cli.getargs,
            ["-v", "2", "--pkg_exact", "openssl", "--repository", "nix_unstable"],
        ),
        (repology_cve.getargs, ["-v", "2", "openssl", "3.1.0"]),
        (provenance_main.getargs, ["-v", "2", ".#pkg"]),
    ],
)
def test_cli_verbose_short_flag_sets_verbosity(getargs, argv):
    assert getargs(argv).verbose == 2


@pytest.mark.parametrize(
    ("getargs", "argv", "expected_out"),
    [
        (nixgraph_main.getargs, ["-o", "graph.dot", ".#pkg"], "graph.dot"),
        (nixmeta_main._getargs, ["-o", "meta.csv"], "meta.csv"),
        (nix_outdated.getargs, ["-o", "nix_outdated.csv", ".#pkg"], "nix_outdated.csv"),
        (vulnxscan_cli.getargs, ["-o", "vulns.csv", ".#pkg"], "vulns.csv"),
        (osv_cli.getargs, ["-o", "osv.csv", "sbom.json"], "osv.csv"),
        (
            repology_cli.getargs,
            [
                "-o",
                "repology.csv",
                "--pkg_exact",
                "openssl",
                "--repository",
                "nix_unstable",
            ],
            "repology.csv",
        ),
        (
            repology_cve.getargs,
            ["-o", "repology_cves.csv", "openssl", "3.1.0"],
            "repology_cves.csv",
        ),
        (
            provenance_main.getargs,
            ["-o", "provenance.json", ".#pkg"],
            "provenance.json",
        ),
    ],
)
def test_single_output_clis_accept_short_o_alias(getargs, argv, expected_out):
    assert _stringify(getargs(argv).out) == expected_out


def test_repology_cli_uses_uppercase_v_for_version_filter():
    args = repology_cli.getargs(
        [
            "-V",
            "^3\\.1\\.",
            "--pkg_exact",
            "openssl",
            "--repository",
            "nix_unstable",
        ]
    )

    assert args.re_version == "^3\\.1\\."
