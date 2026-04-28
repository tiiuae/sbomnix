#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

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


CLI_ARG_CASES = [
    (sbomnix_main.getargs, [".#pkg"]),
    (nixgraph_main.getargs, [".#pkg"]),
    (nixmeta_main._getargs, []),
    (nix_outdated.getargs, [".#pkg"]),
    (vulnxscan_cli.getargs, [".#pkg"]),
    (osv_cli.getargs, ["sbom.json"]),
    (
        repology_cli.getargs,
        ["--pkg_exact", "openssl", "--repository", "nix_unstable"],
    ),
    (repology_cve.getargs, ["openssl", "3.1.0"]),
    (provenance_main.getargs, [".#pkg"]),
]


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
    ("getargs", "base_argv"),
    CLI_ARG_CASES,
)
def test_cli_verbose_default_is_normal_info(getargs, base_argv):
    assert getargs(base_argv).verbose == 0


@pytest.mark.parametrize(
    ("getargs", "base_argv"),
    CLI_ARG_CASES,
)
@pytest.mark.parametrize(
    "verbose_argv",
    [
        ["-v"],
        ["--verbose=1"],
        ["--verbose", "1"],
    ],
)
def test_cli_verbose_level_one_forms_match(getargs, base_argv, verbose_argv):
    assert getargs([*verbose_argv, *base_argv]).verbose == 1


@pytest.mark.parametrize(
    ("getargs", "base_argv"),
    CLI_ARG_CASES,
)
@pytest.mark.parametrize(
    "verbose_argv",
    [
        ["-v", "-v"],
        ["-vv"],
        ["-v", "2"],
        ["--verbose=2"],
        ["--verbose", "2"],
    ],
)
def test_cli_verbose_level_two_forms_match(getargs, base_argv, verbose_argv):
    assert getargs([*verbose_argv, *base_argv]).verbose == 2


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
