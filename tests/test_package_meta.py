#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for package metadata lookup and identity matching."""

import json
import shutil
import subprocess
from dataclasses import replace

import pandas as pd
import pytest

from common import columns as cols
from sbomnix import flake_metadata, package_meta
from sbomnix import meta as meta_module
from sbomnix import meta_source as meta_source_module
from sbomnix.meta import Meta, NixpkgsMetaSource
from sbomnix.meta_source import NixpkgsMetaSourceResolver


def _lookup(name, pname, version, components=None):
    """Return a lookup key for the given package and component paths."""
    return {
        "name": name,
        "pname": pname,
        "version": version,
        "components": components or [[f"/nix/store/{name}.drv"]],
    }


def _nix_identity(expression):
    """Return [drvPath, outPath...] of the derivation a Nix expression yields."""
    ret = subprocess.run(
        [
            "nix",
            "eval",
            "--json",
            "--impure",
            "--extra-experimental-features",
            "nix-command flakes",
            "--expr",
            f"let drv = {expression}; in [ drv.drvPath ] ++ "
            'map (output: drv.${output}.outPath) (drv.outputs or [ "out" ])',
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(ret.stdout)


def _flake_package_identity(flake_dir, attr):
    """Return the identity of a package output of a test flake."""
    return _nix_identity(
        f'(builtins.getFlake "{flake_dir.as_posix()}")'
        f".packages.{package_meta.nix_system()}.{attr}"
    )


@pytest.fixture
def system():
    """Return the Nix system, skipping the test when nix is not available."""
    if shutil.which("nix") is None:
        pytest.skip("nix is not available")
    return package_meta.nix_system()


def _write_flake(tmp_path, flake):
    flake_dir = tmp_path / "flake"
    flake_dir.mkdir()
    (flake_dir / "flake.nix").write_text(flake, encoding="utf-8")
    return flake_dir


def _shadow_package_set(tmp_path, system):
    """Write a package set with one package and return it with its identity."""
    package_set_path = tmp_path / "package-set.nix"
    package_set_path.write_text(
        """{ system, config ? { } }: {
  shadow = (derivation {
    name = "shadow-1.0";
    inherit system;
    builder = "/bin/sh";
    outputs = [ "out" "dev" ];
    args = [ "-c" "echo out > $out; echo dev > $dev" ];
  }) // {
    pname = "shadow";
    version = "1.0";
    meta.description = "imported";
  };
}
""",
        encoding="utf-8",
    )
    shadow = _nix_identity(
        f'(import {package_set_path.as_posix()} {{ system = "{system}"; }}).shadow'
    )
    return package_set_path, shadow


def test_package_meta_lookup_keys_carry_component_identity():
    df_components = pd.DataFrame(
        [
            {
                cols.NAME: "python3.13-requests-2.32.5",
                cols.PNAME: "python3.13-requests",
                cols.VERSION: "2.32.5",
                cols.STORE_PATH: "/nix/store/requests.drv",
                cols.OUTPUTS: ["/nix/store/requests-out", "/nix/store/requests-dist"],
            },
            {
                cols.NAME: "libcap-ng-0.8.5",
                cols.PNAME: "libcap-ng",
                cols.VERSION: "0.8.5",
                cols.STORE_PATH: "/nix/store/libcap-ng-b.drv",
                cols.OUTPUTS: ["/nix/store/libcap-ng-b-out"],
            },
            {
                cols.NAME: "libcap-ng-0.8.5",
                cols.PNAME: "libcap-ng",
                cols.VERSION: "0.8.5",
                cols.STORE_PATH: "/nix/store/libcap-ng-a.drv",
                cols.OUTPUTS: [],
            },
            {
                cols.NAME: "no-identity-1.0",
                cols.PNAME: "no-identity",
                cols.VERSION: "1.0",
            },
        ]
    )

    lookup_keys = package_meta.package_meta_lookup_keys_for_components(df_components)

    assert lookup_keys == [
        {
            "name": "libcap-ng-0.8.5",
            "pname": "libcap-ng",
            "version": "0.8.5",
            "components": [
                ["/nix/store/libcap-ng-a.drv"],
                ["/nix/store/libcap-ng-b-out", "/nix/store/libcap-ng-b.drv"],
            ],
        },
        {
            "name": "python3.13-requests-2.32.5",
            "pname": "python3.13-requests",
            "version": "2.32.5",
            "components": [
                [
                    "/nix/store/requests-dist",
                    "/nix/store/requests-out",
                    "/nix/store/requests.drv",
                ]
            ],
        },
    ]


def test_package_meta_lookup_keys_keep_dotted_package_names():
    df_components = pd.DataFrame(
        [
            {
                cols.NAME: "python3.13-zope.interface-7.2",
                cols.PNAME: "zope.interface",
                cols.VERSION: "7.2",
                cols.STORE_PATH: "/nix/store/zope-interface.drv",
            },
            {
                cols.NAME: "source.json",
                cols.PNAME: "source.json",
                cols.VERSION: "",
                cols.STORE_PATH: "/nix/store/source-json.drv",
            },
        ]
    )

    lookup_keys = package_meta.package_meta_lookup_keys_for_components(df_components)

    assert lookup_keys == [
        {
            "name": "python3.13-zope.interface-7.2",
            "pname": "zope.interface",
            "version": "7.2",
            "components": [["/nix/store/zope-interface.drv"]],
        }
    ]


def test_request_uses_wrapper_file_for_pure_eval(monkeypatch):
    captured = {}

    def fake_eval_file(eval_file, **kwargs):
        eval_path = package_meta.pathlib.Path(eval_file)
        captured["request"] = json.loads(
            (eval_path.parent / "request.json").read_text(encoding="utf-8")
        )
        captured["eval"] = eval_path.read_text(encoding="utf-8")
        return pd.DataFrame()

    monkeypatch.setattr(package_meta, "_eval_file", fake_eval_file)

    package_meta._eval_package_meta_request(
        {"flakeref": "flake#${bad}", "lookupKeys": []}
    )

    assert captured["request"]["flakeref"] == "flake#${bad}"
    assert "builtins.readFile ./request.json" in captured["eval"]
    assert "requestFile" not in captured["eval"]


def test_try_scan_package_meta_normalizes_current_flake_shorthand(
    monkeypatch, tmp_path
):
    captured = {}

    def fake_eval_package_meta_request(request, **kwargs):
        captured["request"] = request
        return pd.DataFrame()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        package_meta,
        "_eval_package_meta_request",
        fake_eval_package_meta_request,
    )

    package_meta.try_scan_package_meta(
        [_lookup("hello-1.0", "hello", "1.0")],
        flakeref="#hello",
    )

    assert captured["request"]["flakeref"] == f"{tmp_path.as_posix()}#hello"


@pytest.mark.parametrize(
    ("flakeref", "expected_fallback"),
    [
        ("flake#packages.aarch64-linux.foo", "aarch64-linux"),
        ("flake#default", "riscv64-linux"),
    ],
)
def test_try_scan_package_meta_sends_one_request_for_all_systems(
    monkeypatch, flakeref, expected_fallback
):
    captured = []

    def fake_eval_package_meta_request(request, **kwargs):
        captured.append(request)
        return pd.DataFrame()

    monkeypatch.setattr(
        package_meta,
        "_eval_package_meta_request",
        fake_eval_package_meta_request,
    )
    monkeypatch.setattr(package_meta, "nix_system", lambda: "riscv64-linux")

    package_meta.try_scan_package_meta(
        [
            {**_lookup("pkg-x86-1.0", "pkg-x86", "1.0"), "system": "x86_64-linux"},
            {**_lookup("source-patch", "source-patch", ""), "system": "builtin"},
            {**_lookup("pkg-i686-1.0", "pkg-i686", "1.0"), "system": "i686-linux"},
            _lookup("pkg-1.0", "pkg", "1.0"),
        ],
        flakeref=flakeref,
    )

    assert len(captured) == 1
    assert {
        lookup["name"]: lookup["system"] for lookup in captured[0]["lookupKeys"]
    } == {
        "pkg-x86-1.0": "x86_64-linux",
        # Not a Nix system: looked up for the target system.
        "source-patch": expected_fallback,
        "pkg-i686-1.0": "i686-linux",
        "pkg-1.0": expected_fallback,
    }


@pytest.mark.parametrize(
    ("flakeref", "walk_target", "expected"),
    [
        (
            "flake#target",
            True,
            [
                ["packages", "aarch64-linux", "target"],
                ["legacyPackages", "aarch64-linux", "target"],
                ["target"],
            ],
        ),
        (
            'flake#packages.aarch64-linux."my.pkg"^dev',
            True,
            [
                ["packages", "aarch64-linux", "packages", "aarch64-linux", "my.pkg"],
                [
                    "legacyPackages",
                    "aarch64-linux",
                    "packages",
                    "aarch64-linux",
                    "my.pkg",
                ],
                ["packages", "aarch64-linux", "my.pkg"],
            ],
        ),
        (
            "flake",
            True,
            [
                ["packages", "aarch64-linux", "default"],
                ["defaultPackage", "aarch64-linux"],
            ],
        ),
        ("flake#target", False, []),
        (None, True, []),
    ],
)
def test_try_scan_package_meta_requests_target_attr_paths(
    monkeypatch, flakeref, walk_target, expected
):
    captured = {}

    def fake_eval_package_meta_request(request, **kwargs):
        captured["request"] = request
        return pd.DataFrame()

    monkeypatch.setattr(
        package_meta,
        "_eval_package_meta_request",
        fake_eval_package_meta_request,
    )
    monkeypatch.setattr(package_meta, "nix_system", lambda: "aarch64-linux")

    package_meta.try_scan_package_meta(
        [_lookup("pkg-1.0", "pkg", "1.0")],
        flakeref=flakeref,
        walk_target=walk_target,
    )

    assert captured["request"]["targetAttrPaths"] == expected


def test_request_lookup_keys_expand_package_set_candidates():
    lookup = package_meta._request_lookup_keys(
        [_lookup("python3.13-requests-2.32.5", "python3.13-requests", "2.32.5")],
        "x86_64-linux",
    )[0]

    assert lookup["pname"] == "requests"
    assert lookup["candidateTiers"][0] == [
        {
            "attr": "requests",
            "packageSets": ["python313Packages", "python3Packages", ""],
        }
    ]


def test_request_lookup_keys_use_haskell_package_set_hint():
    lookup = package_meta._request_lookup_keys(
        [_lookup("vector-0.13.2.0", "vector", "0.13.2.0")], "x86_64-linux"
    )[0]

    assert lookup["candidateTiers"][-1] == [
        {
            "attr": "vector",
            "packageSets": ["haskellPackages"],
        }
    ]


def test_request_lookup_keys_probe_parsed_name_for_fallback_pname():
    lookup = package_meta._request_lookup_keys(
        [_lookup("foo-1.0", "foo-1.0", "")], "x86_64-linux"
    )[0]

    assert lookup["pname"] == "foo"
    assert lookup["candidateTiers"][0] == [
        {
            "attr": "foo",
            "packageSets": [""],
        }
    ]


def test_request_lookup_keys_keep_qt_hint_before_haskell_shape():
    lookup = package_meta._request_lookup_keys(
        [_lookup("qtbase-6.10.2", "qtbase", "6.10.2")], "x86_64-linux"
    )[0]

    assert lookup["candidateTiers"][0] == [
        {
            "attr": "qtbase",
            "packageSets": ["qt6Packages", "qt6", "kdePackages", ""],
        }
    ]
    assert all(
        "haskellPackages" not in candidate["packageSets"]
        for tier in lookup["candidateTiers"]
        for candidate in tier
    )


def test_request_lookup_keys_probe_kde_packages_for_k_prefixed_frameworks():
    lookup = package_meta._request_lookup_keys(
        [_lookup("kconfig-6.17.0", "kconfig", "6.17.0")], "x86_64-linux"
    )[0]

    assert lookup["candidateTiers"][0] == [
        {
            "attr": "kconfig",
            "packageSets": [""],
        },
        {
            "attr": "kconfig",
            "packageSets": ["kdePackages"],
        },
    ]
    assert all(
        "kdePackages" not in candidate["packageSets"]
        for tier in lookup["candidateTiers"][1:]
        for candidate in tier
    )


def test_request_lookup_keys_keep_haskell_hint_for_k_prefixed_packages():
    lookup = package_meta._request_lookup_keys(
        [_lookup("kan-extensions-5.2.7", "kan-extensions", "5.2.7")], "x86_64-linux"
    )[0]

    assert lookup["candidateTiers"][0] == [
        {
            "attr": "kan-extensions",
            "packageSets": [""],
        },
        {
            "attr": "kan-extensions",
            "packageSets": ["kdePackages"],
        },
    ]
    assert lookup["candidateTiers"][-1] == [
        {
            "attr": "kan-extensions",
            "packageSets": ["haskellPackages"],
        }
    ]


@pytest.mark.parametrize(
    ("buildtime", "expected_description"),
    [
        (False, "runtime match"),
        (True, "buildtime match"),
    ],
)
def test_metadata_requires_exact_component_identity(buildtime, expected_description):
    components = pd.DataFrame(
        [
            {
                cols.STORE_PATH: "/nix/store/component-real.drv",
                cols.OUTPUTS: ["/nix/store/component-real-out"],
            }
        ]
    )
    metadata = pd.DataFrame(
        [
            {
                cols.STORE_PATH: "/nix/store/wrong.drv",
                package_meta.META_OUTPUT_PATH: "/nix/store/component-real-out",
                "meta_description": "runtime match",
            },
            {
                cols.STORE_PATH: "/nix/store/component-real.drv",
                package_meta.META_OUTPUT_PATH: "/nix/store/other-output",
                "meta_description": "buildtime match",
            },
        ]
    )

    matched = package_meta.match_package_metadata_to_components(
        components,
        metadata,
        buildtime=buildtime,
    )

    assert matched.to_dict("records")[0]["meta_description"] == expected_description
    assert package_meta.META_OUTPUT_PATH not in matched.columns


def test_buildtime_metadata_can_fall_back_to_exact_output_identity():
    components = pd.DataFrame(
        [
            {
                cols.STORE_PATH: "/nix/store/component-real.drv",
                cols.OUTPUTS: ["/nix/store/component-real-out"],
            }
        ]
    )
    metadata = pd.DataFrame(
        [
            {
                cols.STORE_PATH: "/nix/store/metadata-drv.drv",
                package_meta.META_OUTPUT_PATH: "/nix/store/component-real-out",
                "meta_description": "output identity match",
            }
        ]
    )

    matched = package_meta.match_package_metadata_to_components(
        components,
        metadata,
        buildtime=True,
    )

    assert matched.to_dict("records")[0]["meta_description"] == (
        "output identity match"
    )
    assert matched.to_dict("records")[0][cols.STORE_PATH] == (
        "/nix/store/component-real.drv"
    )


def test_parse_package_metadata_records_identity_fields():
    df = package_meta.parse_package_metadata(
        json.dumps(
            {
                "derivations": [
                    {
                        "drvPath": "/nix/store/pkg.drv",
                        "outPaths": ["/nix/store/pkg-out", "/nix/store/pkg-dev"],
                        "name": "pkg-1.0",
                        "pname": "pkg",
                        "version": "1.0",
                        "meta": {
                            "cpe": "cpe:2.3:a:pkg_vendor:pkg:1.0:*:*:*:*:*:*:*",
                            "description": "Package",
                            "license": [{"spdxId": "MIT", "shortName": "MIT"}],
                            "maintainers": [{"email": "maintainer@example.invalid"}],
                            "possibleCPEs": [
                                {"cpe": "cpe:2.3:a:pkg_vendor:pkg:1.0:*:*:*:*:*:*:*"},
                                {"cpe": "cpe:2.3:a:pkg_vendor:pkg:1:*:*:*:*:*:*:*"},
                            ],
                        },
                    }
                ]
            }
        )
    )

    assert df[package_meta.META_OUTPUT_PATH].to_list() == [
        "/nix/store/pkg-out",
        "/nix/store/pkg-dev",
    ]
    assert df[cols.STORE_PATH].to_list() == ["/nix/store/pkg.drv"] * 2
    record = df.to_dict("records")[0]
    assert record["meta_description"] == "Package"
    assert record["meta_cpe"] == "cpe:2.3:a:pkg_vendor:pkg:1.0:*:*:*:*:*:*:*"
    assert record["meta_possible_cpes"] == (
        "cpe:2.3:a:pkg_vendor:pkg:1.0:*:*:*:*:*:*:*;"
        "cpe:2.3:a:pkg_vendor:pkg:1:*:*:*:*:*:*:*"
    )
    assert record["meta_license_spdxid"] == "MIT"


def test_package_meta_scans_flake_package_roots_and_preserves_output_metadata(
    tmp_path, system
):
    dep_dir = tmp_path / "dep"
    mk_shadow = """
{ system, description }:
(derivation {
  name = "shadow-1.0";
  inherit system;
  builder = "/bin/sh";
  outputs = [ "out" "dev" ];
  args = [ "-c" "echo out > $out; echo dev > $dev" ];
  inherit description;
}) // {
  pname = "shadow";
  version = "1.0";
  meta.description = description;
  meta.identifiers = {
    cpe = "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*";
    possibleCPEs = [
      { cpe = "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*"; }
    ];
  };
}
"""
    package_set = """{ system, config ? { } }: {
  shadow = import ./mk-shadow.nix { inherit system; description = "imported"; };
}
"""
    flake = """
{
  inputs.dep.url = "path:__DEP__";

  outputs = { self, dep }:
  let
    system = "__SYSTEM__";
  in
    {
    packages.${system} = {
      shadow = import ./mk-shadow.nix {
        inherit system;
        description = "flake-root";
      };
    };
    legacyPackages.${system}.default = throw "unrelated legacy default failed";
  };
}
""".replace("__DEP__", dep_dir.as_posix()).replace("__SYSTEM__", system)
    dep_flake = """
{
  outputs = { self }:
  let
    system = "__SYSTEM__";
  in
    {
    legacyPackages.${system}.shadow = import ./mk-shadow.nix {
      inherit system;
      description = "flake-input-root";
    };
    packages.${system}."input-shadow" = (derivation {
      name = "input-shadow-1.0";
      inherit system;
      builder = "/bin/sh";
      outputs = [ "out" "dev" ];
      args = [ "-c" "echo out > $out; echo dev > $dev" ];
    }) // {
      pname = "input-shadow";
      version = "1.0";
      meta.description = "flake-input";
      meta.identifiers = {
        cpe = "cpe:2.3:a:shadow_project:input-shadow:1.0:*:*:*:*:*:*:*";
        possibleCPEs = [
          { cpe = "cpe:2.3:a:shadow_project:input-shadow:1.0:*:*:*:*:*:*:*"; }
        ];
      };
    };
  };
}
""".replace("__SYSTEM__", system)

    package_set_path = tmp_path / "package-set.nix"
    package_set_path.write_text(package_set, encoding="utf-8")
    (tmp_path / "mk-shadow.nix").write_text(mk_shadow, encoding="utf-8")
    dep_dir.mkdir()
    (dep_dir / "flake.nix").write_text(dep_flake, encoding="utf-8")
    (dep_dir / "mk-shadow.nix").write_text(mk_shadow, encoding="utf-8")
    flake_dir = _write_flake(tmp_path, flake)
    (flake_dir / "mk-shadow.nix").write_text(mk_shadow, encoding="utf-8")

    shadow = _flake_package_identity(flake_dir, "shadow")
    df = package_meta.try_scan_package_meta(
        [_lookup("shadow-1.0", "shadow", "1.0", [shadow])],
        flakeref=flake_dir.as_posix(),
        nixpkgs_path=package_set_path,
        impure=True,
    )

    assert df is not None
    assert df[cols.STORE_PATH].to_list() == [shadow[0], shadow[0]]
    assert df[package_meta.META_OUTPUT_PATH].to_list() == shadow[1:]
    assert df["meta_description"].to_list() == ["flake-root", "flake-root"]
    assert df["meta_cpe"].to_list() == [
        "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*",
    ]
    assert df[cols.PNAME].to_list() == ["shadow", "shadow"]
    assert df[cols.VERSION].to_list() == ["1.0", "1.0"]

    df_fallback = package_meta.try_scan_package_meta(
        [_lookup("shadow-1.0", "shadow-1.0", "", [shadow])],
        flakeref=flake_dir.as_posix(),
        nixpkgs_path=package_set_path,
        impure=True,
    )

    assert df_fallback is not None
    assert df_fallback["meta_description"].to_list() == ["flake-root", "flake-root"]
    assert df_fallback[cols.PNAME].to_list() == ["shadow", "shadow"]
    assert df_fallback[cols.VERSION].to_list() == ["1.0", "1.0"]

    # Package roots of flake inputs are searched after the base roots.
    input_shadow = _flake_package_identity(dep_dir, "input-shadow")
    df_input = package_meta.try_scan_package_meta(
        [_lookup("input-shadow-1.0", "input-shadow", "1.0", [input_shadow])],
        flakeref=flake_dir.as_posix(),
        nixpkgs_path=package_set_path,
        impure=True,
    )

    assert df_input is not None
    assert df_input["meta_description"].to_list() == ["flake-input", "flake-input"]
    assert df_input["meta_cpe"].to_list() == [
        "cpe:2.3:a:shadow_project:input-shadow:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:shadow_project:input-shadow:1.0:*:*:*:*:*:*:*",
    ]
    assert df_input[cols.PNAME].to_list() == ["input-shadow", "input-shadow"]
    assert df_input[cols.VERSION].to_list() == ["1.0", "1.0"]

    # Same-named components are found in every package root that has one.
    same_named = [
        shadow,
        _nix_identity(
            f'(import {package_set_path.as_posix()} {{ system = "{system}"; }}).shadow'
        ),
        _nix_identity(
            f'(builtins.getFlake "{dep_dir.as_posix()}").legacyPackages.{system}.shadow'
        ),
    ]
    df_all = package_meta.try_scan_package_meta(
        [_lookup("shadow-1.0", "shadow", "1.0", same_named)],
        flakeref=flake_dir.as_posix(),
        nixpkgs_path=package_set_path,
        impure=True,
    )

    assert df_all is not None
    assert set(df_all["meta_description"]) == {
        "flake-root",
        "imported",
        "flake-input-root",
    }

    # A same-named component with another identity gets no metadata.
    df_other = package_meta.try_scan_package_meta(
        [_lookup("shadow-1.0", "shadow", "1.0", [["/nix/store/other-shadow.drv"]])],
        flakeref=flake_dir.as_posix(),
        nixpkgs_path=package_set_path,
        impure=True,
    )

    assert df_other is not None
    assert df_other.empty


def test_package_meta_preserves_top_level_possible_cpes(tmp_path, system):
    flake = """
{
  outputs = { self }:
  let
    system = "__SYSTEM__";
  in
    {
    packages.${system}.shadow = (derivation {
      name = "shadow-1.0";
      inherit system;
      builder = "/bin/sh";
      args = [ "-c" "echo out > $out" ];
    }) // {
      pname = "shadow";
      version = "1.0";
      meta.possibleCPEs = [
        { cpe = "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*"; }
      ];
    };
  };
}
""".replace("__SYSTEM__", system)
    flake_dir = _write_flake(tmp_path, flake)

    shadow = _flake_package_identity(flake_dir, "shadow")
    df = package_meta.try_scan_package_meta(
        [_lookup("shadow-1.0", "shadow", "1.0", [shadow])],
        flakeref=flake_dir.as_posix(),
        impure=True,
    )

    assert df is not None
    assert df["meta_possible_cpes"].to_list() == [
        "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*"
    ]


def test_package_meta_ignores_unreadable_identifier_attrs(tmp_path, system):
    flake = """
{
  outputs = { self }:
  let
    system = "__SYSTEM__";
  in
    {
    packages.${system}.shadow = (derivation {
      name = "shadow-1.0";
      inherit system;
      builder = "/bin/sh";
      args = [ "-c" "echo out > $out" ];
    }) // {
      pname = "shadow";
      version = "1.0";
      meta.description = "shadow description";
      meta.identifiers = throw "bad";
    };
  };
}
""".replace("__SYSTEM__", system)
    flake_dir = _write_flake(tmp_path, flake)

    shadow = _flake_package_identity(flake_dir, "shadow")
    df = package_meta.try_scan_package_meta(
        [_lookup("shadow-1.0", "shadow", "1.0", [shadow])],
        flakeref=flake_dir.as_posix(),
        impure=True,
    )

    assert df is not None
    assert df["meta_description"].to_list() == ["shadow description"]
    assert df["meta_cpe"].to_list() == [""]
    assert df["meta_possible_cpes"].to_list() == [""]


def test_package_meta_falls_back_from_empty_legacy_cpe_fields(tmp_path, system):
    flake = """
{
  outputs = { self }:
  let
    system = "__SYSTEM__";
  in
    {
    packages.${system}.shadow = (derivation {
      name = "shadow-1.0";
      inherit system;
      builder = "/bin/sh";
      args = [ "-c" "echo out > $out" ];
    }) // {
      pname = "shadow";
      version = "1.0";
      meta.cpe = "";
      meta.possibleCPEs = [ ];
      meta.identifiers = {
        cpe = "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*";
        possibleCPEs = [
          { cpe = "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*"; }
        ];
      };
    };
  };
}
""".replace("__SYSTEM__", system)
    flake_dir = _write_flake(tmp_path, flake)

    shadow = _flake_package_identity(flake_dir, "shadow")
    df = package_meta.try_scan_package_meta(
        [_lookup("shadow-1.0", "shadow", "1.0", [shadow])],
        flakeref=flake_dir.as_posix(),
        impure=True,
    )

    assert df is not None
    assert df["meta_cpe"].to_list() == [
        "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*"
    ]
    assert df["meta_possible_cpes"].to_list() == [
        "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*"
    ]


_WALK_FLAKE = """
{
  outputs = { self }:
  let
    system = "__SYSTEM__";
    mkPackage = name: version: attrs: (derivation ({
      name = "${name}-${version}";
      inherit system;
      builder = "/bin/sh";
      args = [ "-c" "echo ${name} > $out" ];
    } // attrs)) // {
      pname = name;
      inherit version;
      meta.description = "${name} description";
    };
    # Reachable only as derivation values, not through any package attr.
    patched = mkPackage "patched" "1.0" { };
    private = mkPackage "private" "2.0" { nested = [ [ patched ] ]; };
    structured = mkPackage "structured" "3.0" { };
    tool = mkPackage "tool" "4.0" { buildInputs = [ private ]; };
    split = mkPackage "split" "5.0" { outputs = [ "out" "dev" ]; };
  in
    {
    packages.${system} = {
      inherit tool split;
      patched = mkPackage "patched" "1.0" { variant = "other"; };
      # The target name differs from its attr name, and it refers to tool
      # only through string context.
      doc = mkPackage "ghaf-docs" "0.1.0" {
        __structuredAttrs = true;
        # The output value does not carry the metadata merged into split.
        deps.inner = [ structured (split.dev // { meta.platforms = [ ]; }) ];
        script = "${tool}";
      };
    };
  };
}
"""


def test_package_meta_walks_target_and_named_derivations(tmp_path, system):
    flake_dir = tmp_path / "flake"
    flake_dir.mkdir()
    (flake_dir / "flake.nix").write_text(
        _WALK_FLAKE.replace("__SYSTEM__", system), encoding="utf-8"
    )
    flake = f'(builtins.getFlake "{flake_dir.as_posix()}")'
    doc = _flake_package_identity(flake_dir, "doc")
    tool = _flake_package_identity(flake_dir, "tool")
    split = _flake_package_identity(flake_dir, "split")
    private = _nix_identity(f"builtins.head {flake}.packages.{system}.tool.buildInputs")
    patched = _nix_identity(
        f"builtins.head (builtins.head (builtins.head "
        f"{flake}.packages.{system}.tool.buildInputs).nested)"
    )
    structured = _nix_identity(
        f"builtins.head {flake}.packages.{system}.doc.drvAttrs.deps.inner"
    )
    lookup_keys = [
        _lookup("ghaf-docs-0.1.0", "ghaf-docs", "0.1.0", [doc]),
        _lookup("patched-1.0", "patched", "1.0", [patched]),
        _lookup("private-2.0", "private", "2.0", [private]),
        _lookup("split-5.0", "split", "5.0", [split]),
        _lookup("structured-3.0", "structured", "3.0", [structured]),
        _lookup("tool-4.0", "tool", "4.0", [tool]),
    ]

    for flakeref in (
        f"{flake_dir.as_posix()}#packages.{system}.doc",
        f"{flake_dir.as_posix()}#doc",
    ):
        df = package_meta.try_scan_package_meta(
            lookup_keys,
            flakeref=flakeref,
            impure=True,
        )

        assert df is not None
        assert dict(zip(df[cols.STORE_PATH], df["meta_description"], strict=True)) == {
            # The target and what it holds as derivation values.
            doc[0]: "ghaf-docs description",
            structured[0]: "structured description",
            # Found by attr name.
            tool[0]: "tool description",
            # Walked as a value without a description, so found by attr name.
            split[0]: "split description",
            # Dependencies of the derivation found by attr name.
            private[0]: "private description",
            patched[0]: "patched description",
        }

    # Without the target walk only attr names and their dependencies remain.
    df = package_meta.try_scan_package_meta(
        lookup_keys,
        flakeref=f"{flake_dir.as_posix()}#doc",
        walk_target=False,
        impure=True,
    )

    assert df is not None
    assert set(df[cols.STORE_PATH]) == {tool[0], private[0], patched[0], split[0]}

    # Package roots are not evaluated when the walk reaches every component.
    broken_package_set = tmp_path / "broken-package-set.nix"
    broken_package_set.write_text("{ ... }: { }.missing\n", encoding="utf-8")
    df = package_meta.try_scan_package_meta(
        lookup_keys[:1],
        flakeref=f"{flake_dir.as_posix()}#doc",
        nixpkgs_path=broken_package_set,
        impure=True,
    )

    assert df is not None
    assert df[cols.STORE_PATH].to_list() == [doc[0]]


def test_package_meta_ignores_broken_optional_flake_package_roots(tmp_path, system):
    flake = """
{
  outputs = { self }:
  let
    system = "__SYSTEM__";
  in
    {
    packages.${system} = throw "broken package root";
    legacyPackages.${system} = throw "broken legacy package root";
  };
}
""".replace("__SYSTEM__", system)
    package_set_path, shadow = _shadow_package_set(tmp_path, system)
    flake_dir = _write_flake(tmp_path, flake)
    df = package_meta.try_scan_package_meta(
        [_lookup("shadow-1.0", "shadow", "1.0", [shadow])],
        flakeref=flake_dir.as_posix(),
        nixpkgs_path=package_set_path,
        impure=True,
    )

    assert df is not None
    assert df["meta_description"].to_list() == ["imported", "imported"]
    assert df[cols.PNAME].to_list() == ["shadow", "shadow"]
    assert df[cols.VERSION].to_list() == ["1.0", "1.0"]


def test_package_meta_retries_without_target_walk_when_scan_fails(
    tmp_path, system, monkeypatch
):
    # A missing attribute is an error that builtins.tryEval does not catch.
    flake = """
{
  outputs = { self }: {
    packages.__SYSTEM__.doc = { }.missing;
  };
}
""".replace("__SYSTEM__", system)
    package_set_path, shadow = _shadow_package_set(tmp_path, system)
    flake_dir = _write_flake(tmp_path, flake)
    requests = []
    eval_package_meta_request = package_meta._eval_package_meta_request

    def record_request(request, **kwargs):
        requests.append(request)
        return eval_package_meta_request(request, **kwargs)

    monkeypatch.setattr(package_meta, "_eval_package_meta_request", record_request)

    df = Meta()._scan_package_source(
        NixpkgsMetaSource(method="flakeref-lock", path=package_set_path.as_posix()),
        [_lookup("shadow-1.0", "shadow", "1.0", [shadow])],
        flakeref=f"{flake_dir.as_posix()}#doc",
        impure=True,
    )

    assert df is not None
    assert df["meta_description"].to_list() == ["imported", "imported"]
    assert [
        (bool(request["targetAttrPaths"]), request["searchInputs"])
        for request in requests
    ] == [(True, True), (False, False)]


@pytest.mark.parametrize(
    ("names", "expected_walk"),
    [
        (["hello-2.12", "glibc-2.40"], True),
        # A NixOS system references its packages through string context.
        (["ghaf-host-disko-images", "nixos-system-ghaf-host-25.11"], False),
    ],
)
def test_target_walk_is_skipped_for_nixos_systems(monkeypatch, names, expected_walk):
    captured = {}

    def fake_scan_package_meta(_lookup_keys, **kwargs):
        captured.update(kwargs)
        return pd.DataFrame()

    monkeypatch.setattr(meta_module, "try_scan_package_meta", fake_scan_package_meta)
    meta = Meta()
    monkeypatch.setattr(
        meta,
        "_resolve_source",
        lambda **_kwargs: NixpkgsMetaSource(
            method="flakeref-lock",
            path="/nix/store/nixpkgs",
        ),
    )
    components = pd.DataFrame(
        [
            {
                cols.NAME: name,
                cols.PNAME: name,
                cols.VERSION: "",
                cols.STORE_PATH: f"/nix/store/{name}.drv",
                cols.OUTPUTS: [f"/nix/store/{name}"],
            }
            for name in names
        ]
    )

    meta.get_package_meta_with_source(
        components=components,
        buildtime=False,
        flakeref="./flake#target",
    )

    assert captured["walk_target"] is expected_walk


def test_expression_source_cache_requires_expression_identity():
    lookup_keys = [_lookup("pkg-1.0", "pkg", "1.0")]
    source = NixpkgsMetaSource(
        method="flakeref-target",
        path="/nix/store/source",
        flakeref="flake#nixosConfigurations.host.pkgs.path",
        flakeref_cache_key="path:/nix/store/flake#nixosConfigurations.host",
        expression='builtins.getFlake "flake"',
    )

    assert Meta._package_cache_key(source, lookup_keys) is None

    cache_key = Meta._package_cache_key(
        replace(
            source,
            expression_cache_key='nixos-pkgs:["path:/nix/store/flake","host"]',
        ),
        lookup_keys,
    )

    assert cache_key is not None
    assert "nixos-pkgs:" in cache_key
    assert "/nix/store/source" not in cache_key


def test_mutable_flakeref_cache_uses_locked_identity():
    source = NixpkgsMetaSource(method="flakeref-lock", path="/nix/store/nixpkgs")
    stable_source = replace(
        source,
        flakeref_cache_key="path:/nix/store/source?narHash=sha256-test#default",
    )
    lookup_keys = [_lookup("pkg-1.0", "pkg", "1.0")]

    assert Meta._package_cache_key(source, lookup_keys) is None

    cache_key = Meta._package_cache_key(stable_source, lookup_keys)
    assert cache_key is not None
    # The target attr is part of the key: the scan walks the target.
    assert "path:/nix/store/source?narHash=sha256-test#default" in cache_key
    # So is whether the target is walked.
    assert cache_key != Meta._package_cache_key(
        stable_source, lookup_keys, walk_target=False
    )
    assert (
        meta_module._package_scan_flakeref(
            stable_source,
            "./flake#default",
        )
        == "path:/nix/store/source?narHash=sha256-test#default"
    )


def test_package_metadata_cache_reuses_identical_scans(monkeypatch):
    class NullLock:
        lock_file = "test-lock"

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc, _traceback):
            return False

    class FakeDfCache:
        def __init__(self):
            self.values = {}

        def get(self, key):
            return self.values.get(key)

        def set(self, key, value, ttl=None):
            del ttl
            self.values[key] = value.copy(deep=True)

    lookup_a = _lookup("alpha-1.0", "alpha", "1.0")
    lookup_b = _lookup("beta-1.0", "beta", "1.0")
    scan_calls = []
    scan_results = []

    def fake_scan_package_meta(lookup_keys, **kwargs):
        scan_calls.append(
            ([lookup_key["name"] for lookup_key in lookup_keys], kwargs["flakeref"])
        )
        if scan_results:
            return scan_results.pop()
        return pd.DataFrame(
            [{cols.NAME: lookup_key["name"]} for lookup_key in lookup_keys]
        )

    monkeypatch.setattr(
        meta_module,
        "try_scan_package_meta",
        fake_scan_package_meta,
    )
    meta = Meta()
    meta.lock = NullLock()
    meta.cache = FakeDfCache()
    alpha = "path:/nix/store/source?narHash=sha256-test#alpha"
    beta = "path:/nix/store/source?narHash=sha256-test#beta"

    def scan(lookup_keys, flakeref):
        source = NixpkgsMetaSource(
            method="flakeref-lock",
            path="/nix/store/nixpkgs",
            flakeref_cache_key=flakeref,
        )
        return meta._scan_package_source(source, lookup_keys, flakeref=flakeref)

    df_first = scan([lookup_a, lookup_b], alpha)
    df_again = scan([lookup_a, lookup_b], alpha)
    assert df_again.equals(df_first)
    assert scan_calls == [(["alpha-1.0", "beta-1.0"], alpha)]

    # Another component set or another target is another scan.
    scan([lookup_a], alpha)
    scan([lookup_a, lookup_b], beta)
    assert scan_calls[1:] == [
        (["alpha-1.0"], alpha),
        (["alpha-1.0", "beta-1.0"], beta),
    ]

    # Component identity is part of the lookup set.
    scan([_lookup("alpha-1.0", "alpha", "1.0", [["/nix/store/other.drv"]])], alpha)
    assert len(scan_calls) == 4

    # A failed scan is retried, and the retry result is not cached.
    scan_results.append(None)
    assert scan([lookup_b], alpha) is not None
    assert len(scan_calls) == 6
    assert scan([lookup_b], alpha) is not None
    assert len(scan_calls) == 7


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        # A clean git tree keeps its revision.
        (
            {
                "path": "/nix/store/source",
                "locked": {"narHash": "sha256-test", "rev": "a" * 40, "type": "git"},
                "url": f"git+file:///repo?ref=refs/heads/main&rev={'a' * 40}&shallow=1",
            },
            f"git+file:///repo?ref=refs/heads/main&rev={'a' * 40}&shallow=1",
        ),
        (
            {
                "path": "/nix/store/source",
                "locked": {"narHash": "sha256-test", "rev": "b" * 40, "type": "github"},
                "lockedUrl": f"github:owner/repo/{'b' * 40}?narHash=sha256-test",
                "url": "ignored",
            },
            f"github:owner/repo/{'b' * 40}?narHash=sha256-test",
        ),
        # A dirty tree has no revision to pin.
        (
            {
                "path": "/nix/store/source",
                "locked": {
                    "narHash": "sha256-test",
                    "dirtyRev": f"{'c' * 40}-dirty",
                    "dir": "sub/dir",
                    "type": "git",
                },
                "url": "git+file:///repo?dir=sub/dir",
            },
            "path:/nix/store/source?narHash=sha256-test&dir=sub/dir",
        ),
        ({"path": "/home/user/repo", "locked": {"narHash": "sha256-test"}}, None),
    ],
)
def test_locked_flake_ref_keeps_pinned_revision(monkeypatch, metadata, expected):
    monkeypatch.setattr(
        NixpkgsMetaSourceResolver,
        "_nix_flake_metadata",
        staticmethod(lambda _flake, *, impure=False: metadata),
    )

    locked_ref = NixpkgsMetaSourceResolver._locked_flake_ref_from_metadata(".")

    assert locked_ref == expected
    if expected:
        assert NixpkgsMetaSourceResolver._flake_ref_has_stable_lock(expected)
        assert Meta._package_cache_key(
            NixpkgsMetaSource(
                method="flakeref-lock",
                path="/nix/store/nixpkgs",
                flakeref_cache_key=f"{expected}#default",
            ),
            [_lookup("pkg-1.0", "pkg", "1.0")],
        )


def test_registry_flakeref_cache_key_uses_locked_identity(monkeypatch):
    def fake_locked_ref(flake, *, impure=False):
        assert flake == "nixpkgs"
        assert impure is False
        return "path:/nix/store/registry-source?narHash=sha256-registry"

    monkeypatch.setattr(
        NixpkgsMetaSourceResolver,
        "_locked_flake_ref_from_metadata",
        staticmethod(fake_locked_ref),
    )

    assert (
        NixpkgsMetaSourceResolver._stable_flakeref_cache_key("nixpkgs#firefox")
        == "path:/nix/store/registry-source?narHash=sha256-registry#firefox"
    )
    # A ref that pins its content is kept as it is.
    pinned = "github:owner/repo?narHash=sha256-test#firefox"
    assert NixpkgsMetaSourceResolver._stable_flakeref_cache_key(pinned) == pinned


def test_current_flake_shorthand_source_resolution_uses_dot(monkeypatch, tmp_path):
    nixpkgs_path = tmp_path / "nixpkgs"
    (nixpkgs_path / "lib").mkdir(parents=True)
    (nixpkgs_path / "lib" / ".version").write_text("25.11\n", encoding="utf-8")
    resolved_refs = []
    locked_refs = []

    def fake_nixref_to_nixpkgs_path(nixref):
        resolved_refs.append(nixref)
        return nixpkgs_path

    def fake_locked_ref(flake, *, impure=False):
        locked_refs.append((flake, impure))
        return "path:/nix/store/current-flake?narHash=sha256-current"

    monkeypatch.setattr(
        meta_source_module,
        "nixref_to_nixpkgs_path",
        fake_nixref_to_nixpkgs_path,
    )
    monkeypatch.setattr(
        NixpkgsMetaSourceResolver,
        "_locked_flake_ref_from_metadata",
        staticmethod(fake_locked_ref),
    )

    source = NixpkgsMetaSourceResolver().resolve_flakeref_lock_source("#hello")

    assert resolved_refs == [".#hello"]
    assert locked_refs == [(".", False)]
    assert source.method == "flakeref-lock"
    assert source.path == nixpkgs_path.as_posix()
    assert source.flakeref == ".#hello"
    assert source.flakeref_cache_key == (
        "path:/nix/store/current-flake?narHash=sha256-current#hello"
    )
    assert source.version == "25.11"


def test_nixref_to_nixpkgs_path_normalizes_current_flake_shorthand():
    metadata_refs = []

    def fake_get_flake_metadata(flakeref):
        metadata_refs.append(flakeref)
        return {
            "path": "/nix/store/current-nixpkgs",
            "description": "A collection of packages for the Nix package manager",
        }

    nixpkgs_path = flake_metadata.nixref_to_nixpkgs_path(
        "#hello",
        get_flake_metadata_fn=fake_get_flake_metadata,
    )

    assert metadata_refs == ["."]
    assert nixpkgs_path.as_posix() == "/nix/store/current-nixpkgs"


def test_get_nixpkgs_flakeref_keeps_shallow_git_lock():
    meta_json = {
        "locks": {
            "root": "root",
            "nodes": {
                "root": {"inputs": {"nixpkgs": "nixpkgs"}},
                "nixpkgs": {
                    "locked": {
                        "narHash": "sha256-test",
                        "ref": "nixos-26.05",
                        "rev": "abc123",
                        "shallow": True,
                        "type": "git",
                        "url": "https://github.com/NixOS/nixpkgs",
                    }
                },
            },
        }
    }

    assert flake_metadata.get_nixpkgs_flakeref(meta_json) == (
        "git+https://github.com/NixOS/nixpkgs?ref=nixos-26.05&rev=abc123&shallow=1"
    )


# From `nix-store --print-fixed-path --recursive sha256 <narHash> source`.
LOCKED_NIXPKGS_STORE_PATH = "/nix/store/fjr02205wq70r3vghhfbfzv5g97nr4ya-source"
LOCKED_NIXPKGS_STORE_REF = (
    f"path:{LOCKED_NIXPKGS_STORE_PATH}"
    "?narHash=sha256-Mh0PUaIv4nFY%2B8wAGonaEh8iBzwsmdNlwjVHmFg1Biw%3D"
)
LOCKED_NIXPKGS_GIT_REF = (
    "git+https://github.com/NixOS/nixpkgs?ref=nixos-26.05&rev=abc123"
)


@pytest.mark.parametrize(
    ("store_path_exists", "store_read_ok", "expected_refs"),
    [
        (True, True, [".", LOCKED_NIXPKGS_STORE_REF]),
        (False, True, [".", LOCKED_NIXPKGS_GIT_REF]),
        (True, False, [".", LOCKED_NIXPKGS_STORE_REF, LOCKED_NIXPKGS_GIT_REF]),
    ],
    ids=["store", "no-store", "store-read-fails"],
)
def test_nixref_to_nixpkgs_path_prefers_locked_nixpkgs_in_store(
    store_path_exists, store_read_ok, expected_refs
):
    metadata_refs = []

    def fake_get_flake_metadata(flakeref):
        metadata_refs.append(flakeref)
        if flakeref == LOCKED_NIXPKGS_STORE_REF and not store_read_ok:
            return None
        if flakeref != ".":
            return {
                "path": LOCKED_NIXPKGS_STORE_PATH,
                "description": "A collection of packages for the Nix package manager",
            }
        return {
            "path": "/nix/store/target-flake",
            "locks": {
                "root": "root",
                "nodes": {
                    "root": {"inputs": {"nixpkgs": "nixpkgs"}},
                    "nixpkgs": {
                        "locked": {
                            "narHash": "sha256-Mh0PUaIv4nFY+8wAGonaEh8iBzwsmdNlwjVHmFg1Biw=",
                            "ref": "nixos-26.05",
                            "rev": "abc123",
                            "type": "git",
                            "url": "https://github.com/NixOS/nixpkgs",
                        }
                    },
                },
            },
        }

    nixpkgs_path = flake_metadata.nixref_to_nixpkgs_path(
        ".#hello",
        get_flake_metadata_fn=fake_get_flake_metadata,
        path_exists_fn=lambda path: (
            store_path_exists and path == LOCKED_NIXPKGS_STORE_PATH
        ),
    )

    assert metadata_refs == expected_refs
    assert nixpkgs_path.as_posix() == LOCKED_NIXPKGS_STORE_PATH
