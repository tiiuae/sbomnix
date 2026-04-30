#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for shared CLI conventions."""

import re
import subprocess
from pathlib import Path

import pytest

from common.pkgmeta import _dev_version, get_py_pkg_version
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


_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEV_VERSION_RE = re.compile(
    r"^(?P<base>\d+\.\d+\.\d+)\+g(?P<hash>[0-9a-f]+)(?P<dirty>\.dirty)?$"
)


def test_dev_version_format_matches_nix_package_format():
    """_dev_version() must produce the same PEP 440 local-version format as
    the Nix postPatch hook so that devshell and packaged invocations report
    identical strings for the same checkout.

    Expected format: <semver>+g<hash>[.dirty]
    The '.dirty' suffix matches what pip writes to METADATA after normalising
    the '-dirty' suffix that the Nix dirtyShortRev attribute appends.
    """
    version = _dev_version()
    m = _DEV_VERSION_RE.match(version)
    assert m, f"_dev_version() returned {version!r}; expected <semver>+g<hash>[.dirty]"

    expected_base = (_REPO_ROOT / "VERSION").read_text().strip()
    assert m.group("base") == expected_base, (
        f"base {m.group('base')!r} does not match VERSION file {expected_base!r}"
    )

    expected_hash = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
        cwd=_REPO_ROOT,
    ).stdout.strip()
    assert m.group("hash") == expected_hash, (
        f"hash {m.group('hash')!r} does not match HEAD {expected_hash!r}"
    )

    is_dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            check=True,
            cwd=_REPO_ROOT,
        ).stdout.strip()
    )
    assert bool(m.group("dirty")) == is_dirty, (
        f"dirty flag in {version!r} does not match working-tree state (dirty={is_dirty})"
    )


@pytest.mark.slow
def test_dev_version_parity_with_nix_package_version():
    """_dev_version() must equal the version written into the Nix-built
    package's dist-info METADATA for the same checkout.

    This exercises the full packaging pipeline — gitSuffix in
    nix/packages.nix, the postPatch VERSION rewrite, setuptools wheel build,
    and pip normalisation — and compares the result with _dev_version(), so
    any drift between the Nix packaging path and the Python fallback is caught.
    Evaluating the Nix version attribute alone is not sufficient because
    postPatch could write a different string than the attribute implies.
    """
    system = subprocess.run(
        ["nix", "eval", "--impure", "--raw", "--expr", "builtins.currentSystem"],
        capture_output=True,
        text=True,
        check=True,
        cwd=_REPO_ROOT,
    ).stdout.strip()
    out_path = subprocess.run(
        [
            "nix",
            "build",
            f".#packages.{system}.sbomnix",
            "--print-out-paths",
            "--no-link",
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=_REPO_ROOT,
    ).stdout.strip()

    metadata_files = list(
        Path(out_path).glob("lib/python*/site-packages/sbomnix-*.dist-info/METADATA")
    )
    assert metadata_files, f"no sbomnix dist-info METADATA found under {out_path}"
    version_line = next(
        line
        for line in metadata_files[0].read_text().splitlines()
        if line.startswith("Version:")
    )
    installed_version = version_line.split(":", 1)[1].strip()

    assert _dev_version() == installed_version, (
        f"devshell version {_dev_version()!r} != "
        f"installed METADATA version {installed_version!r}"
    )


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
