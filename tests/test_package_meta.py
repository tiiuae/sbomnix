#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for package metadata lookup and identity matching."""

import json
import shutil
from dataclasses import replace

import pandas as pd
import pytest

from common import columns as cols
from sbomnix import flake_metadata, package_meta
from sbomnix import meta as meta_module
from sbomnix import meta_source as meta_source_module
from sbomnix.meta import Meta, NixpkgsMetaSource
from sbomnix.meta_source import NixpkgsMetaSourceResolver


def test_package_meta_lookup_keys_stay_compact():
    df_components = pd.DataFrame(
        [
            {
                cols.NAME: "python3.13-requests-2.32.5",
                cols.PNAME: "python3.13-requests",
                cols.VERSION: "2.32.5",
            },
            {
                cols.NAME: "libcap-ng-0.8.5",
                cols.PNAME: "libcap-ng",
                cols.VERSION: "0.8.5",
            },
        ]
    )

    lookup_keys = package_meta.package_meta_lookup_keys_for_components(df_components)

    assert lookup_keys == [
        {
            "name": "libcap-ng-0.8.5",
            "pname": "libcap-ng",
            "version": "0.8.5",
        },
        {
            "name": "python3.13-requests-2.32.5",
            "pname": "python3.13-requests",
            "version": "2.32.5",
        },
    ]


def test_package_meta_lookup_keys_keep_dotted_package_names():
    df_components = pd.DataFrame(
        [
            {
                cols.NAME: "python3.13-zope.interface-7.2",
                cols.PNAME: "zope.interface",
                cols.VERSION: "7.2",
            },
            {
                cols.NAME: "source.json",
                cols.PNAME: "source.json",
                cols.VERSION: "",
            },
        ]
    )

    lookup_keys = package_meta.package_meta_lookup_keys_for_components(df_components)

    assert lookup_keys == [
        {
            "name": "python3.13-zope.interface-7.2",
            "pname": "zope.interface",
            "version": "7.2",
        }
    ]


def test_short_request_escapes_nix_antiquotation(monkeypatch):
    captured = {}

    def fake_eval_request(request_arg, **kwargs):
        captured["request_arg"] = request_arg
        return pd.DataFrame()

    monkeypatch.setattr(package_meta, "_eval_request", fake_eval_request)

    package_meta._eval_package_meta_request(
        {"flakeref": "flake#${bad}", "lookupKeys": []}
    )

    assert r"\${bad}" in captured["request_arg"]


def test_large_request_uses_wrapper_file_for_pure_eval(monkeypatch):
    captured = {}

    def fake_eval_file(eval_file, **kwargs):
        eval_path = package_meta.pathlib.Path(eval_file)
        captured["request_exists"] = (eval_path.parent / "request.json").is_file()
        captured["eval"] = eval_path.read_text(encoding="utf-8")
        return pd.DataFrame()

    monkeypatch.setattr(package_meta, "_eval_file", fake_eval_file)

    package_meta._eval_package_meta_request({"lookupKeys": [{"name": "x" * 30_000}]})

    assert captured["request_exists"] is True
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
        [{"name": "hello-1.0", "pname": "hello", "version": "1.0"}],
        flakeref="#hello",
    )

    assert captured["request"]["flakeref"] == f"{tmp_path.as_posix()}#hello"
    assert "flakePackageAttrPath" not in captured["request"]


@pytest.mark.parametrize(
    ("flakeref", "lookup_keys", "expected_system"),
    [
        (
            "flake#packages.aarch64-linux.foo",
            [{"name": "foo-1.0", "pname": "foo", "version": "1.0"}],
            "aarch64-linux",
        ),
        (
            "flake#default",
            [
                {
                    "name": "foo-1.0",
                    "pname": "foo",
                    "version": "1.0",
                    "system": "aarch64-linux",
                }
            ],
            "aarch64-linux",
        ),
    ],
)
def test_try_scan_package_meta_uses_target_system(
    monkeypatch, flakeref, lookup_keys, expected_system
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

    package_meta.try_scan_package_meta(lookup_keys, flakeref=flakeref)

    assert captured["request"]["system"] == expected_system


def test_try_scan_package_meta_splits_mixed_system_requests(monkeypatch):
    captured = []

    def fake_eval_package_meta_request(request, **kwargs):
        captured.append(request)
        return pd.DataFrame(
            [
                {
                    cols.STORE_PATH: f"/nix/store/{request['system']}.drv",
                    package_meta.META_OUTPUT_PATH: "",
                }
            ]
        )

    monkeypatch.setattr(
        package_meta,
        "_eval_package_meta_request",
        fake_eval_package_meta_request,
    )

    df = package_meta.try_scan_package_meta(
        [
            {
                "name": "pkg-x86-1.0",
                "pname": "pkg-x86",
                "version": "1.0",
                "system": "x86_64-linux",
            },
            {
                "name": "source-patch",
                "pname": "source-patch",
                "version": "",
                "system": "builtin",
            },
            {
                "name": "pkg-aarch-1.0",
                "pname": "pkg-aarch",
                "version": "1.0",
                "system": "aarch64-linux",
            },
        ],
        flakeref="flake#default",
    )

    fallback_system = package_meta.nix_system()
    expected_names_by_system = {
        "aarch64-linux": ["pkg-aarch-1.0"],
        "x86_64-linux": ["pkg-x86-1.0"],
    }
    expected_names_by_system.setdefault(fallback_system, []).append("source-patch")
    names_by_system = {
        request["system"]: [lookup["name"] for lookup in request["lookupKeys"]]
        for request in captured
    }

    assert names_by_system == expected_names_by_system
    assert sorted(df[cols.STORE_PATH].to_list()) == [
        f"/nix/store/{system}.drv" for system in sorted(expected_names_by_system)
    ]


def test_try_scan_package_meta_request_omits_direct_flake_attr_path(monkeypatch):
    captured = {}

    def fake_eval_package_meta_request(request, **kwargs):
        captured["request"] = request
        return pd.DataFrame()

    monkeypatch.setattr(
        package_meta,
        "_eval_package_meta_request",
        fake_eval_package_meta_request,
    )

    package_meta.try_scan_package_meta(
        [{"name": "pkg-1.0", "pname": "pkg", "version": "1.0"}],
        flakeref="flake#expensive-target",
    )

    assert "flakePackageAttrPath" not in captured["request"]


def test_request_lookup_keys_expand_package_set_candidates():
    lookup = package_meta._request_lookup_keys(
        [
            {
                "name": "python3.13-requests-2.32.5",
                "pname": "python3.13-requests",
                "version": "2.32.5",
            }
        ]
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
        [
            {
                "name": "vector-0.13.2.0",
                "pname": "vector",
                "version": "0.13.2.0",
            }
        ]
    )[0]

    assert lookup["collectAllCanonical"] is True
    assert lookup["candidateTiers"][-1] == [
        {
            "attr": "vector",
            "packageSets": ["haskellPackages"],
        }
    ]


def test_request_lookup_keys_probe_parsed_name_for_fallback_pname():
    lookup = package_meta._request_lookup_keys(
        [
            {
                "name": "foo-1.0",
                "pname": "foo-1.0",
                "version": "",
            }
        ]
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
        [
            {
                "name": "qtbase-6.10.2",
                "pname": "qtbase",
                "version": "6.10.2",
            }
        ]
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
    assert "collectAllCanonical" not in lookup


def test_request_lookup_keys_probe_kde_packages_for_k_prefixed_frameworks():
    lookup = package_meta._request_lookup_keys(
        [
            {
                "name": "kconfig-6.17.0",
                "pname": "kconfig",
                "version": "6.17.0",
            }
        ]
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
        [
            {
                "name": "kan-extensions-5.2.7",
                "pname": "kan-extensions",
                "version": "5.2.7",
            }
        ]
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
    assert lookup["collectAllCanonical"] is True


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
                        "path": "/nix/store/pkg-out",
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

    record = df.to_dict("records")[0]
    assert record[cols.STORE_PATH] == "/nix/store/pkg.drv"
    assert record[package_meta.META_OUTPUT_PATH] == "/nix/store/pkg-out"
    assert record["meta_description"] == "Package"
    assert record["meta_cpe"] == "cpe:2.3:a:pkg_vendor:pkg:1.0:*:*:*:*:*:*:*"
    assert record["meta_possible_cpes"] == (
        "cpe:2.3:a:pkg_vendor:pkg:1.0:*:*:*:*:*:*:*;"
        "cpe:2.3:a:pkg_vendor:pkg:1:*:*:*:*:*:*:*"
    )
    assert record["meta_license_spdxid"] == "MIT"


def test_package_meta_scans_flake_package_roots_and_preserves_output_metadata(tmp_path):
    if shutil.which("nix") is None:
        pytest.skip("nix is not available")

    system = package_meta.nix_system()
    dep_dir = tmp_path / "dep"
    mk_shadow = """
{ system, description }:
(derivation {
  name = "shadow-1.0";
  inherit system;
  builder = "/bin/sh";
  outputs = [ "out" "dev" ];
  args = [ "-c" "echo out > $out; echo dev > $dev" ];
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
    flake_dir = tmp_path / "flake"
    flake_dir.mkdir()
    (flake_dir / "flake.nix").write_text(flake, encoding="utf-8")
    (flake_dir / "mk-shadow.nix").write_text(mk_shadow, encoding="utf-8")

    df = package_meta.try_scan_package_meta(
        [{"name": "shadow-1.0", "pname": "shadow", "version": "1.0"}],
        flakeref=flake_dir.as_posix(),
        nixpkgs_path=package_set_path,
        impure=True,
    )

    assert df is not None
    assert df["meta_description"].to_list() == ["flake-root", "flake-root"]
    assert df["meta_cpe"].to_list() == [
        "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*",
    ]
    assert df[cols.PNAME].to_list() == ["shadow", "shadow"]
    assert df[cols.VERSION].to_list() == ["1.0", "1.0"]

    df_fallback = package_meta.try_scan_package_meta(
        [{"name": "shadow-1.0", "pname": "shadow-1.0", "version": ""}],
        flakeref=flake_dir.as_posix(),
        nixpkgs_path=package_set_path,
        impure=True,
    )

    assert df_fallback is not None
    assert df_fallback["meta_description"].to_list() == ["flake-root", "flake-root"]
    assert df_fallback["meta_cpe"].to_list() == [
        "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*",
    ]
    assert df_fallback[cols.PNAME].to_list() == ["shadow", "shadow"]
    assert df_fallback[cols.VERSION].to_list() == ["1.0", "1.0"]

    df_input = package_meta.try_scan_package_meta(
        [
            {
                "name": "input-shadow-1.0",
                "pname": "input-shadow",
                "version": "1.0",
            }
        ],
        flakeref=flake_dir.as_posix(),
        nixpkgs_path=package_set_path,
        input_roots_only=True,
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


def test_package_meta_preserves_top_level_possible_cpes(tmp_path):
    if shutil.which("nix") is None:
        pytest.skip("nix is not available")

    system = package_meta.nix_system()
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
    flake_dir = tmp_path / "flake"
    flake_dir.mkdir()
    (flake_dir / "flake.nix").write_text(flake, encoding="utf-8")

    df = package_meta.try_scan_package_meta(
        [{"name": "shadow-1.0", "pname": "shadow", "version": "1.0"}],
        flakeref=flake_dir.as_posix(),
        impure=True,
    )

    assert df is not None
    assert df["meta_possible_cpes"].to_list() == [
        "cpe:2.3:a:shadow_project:shadow:1.0:*:*:*:*:*:*:*"
    ]


def test_package_meta_ignores_unreadable_identifier_attrs(tmp_path):
    if shutil.which("nix") is None:
        pytest.skip("nix is not available")

    system = package_meta.nix_system()
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
    flake_dir = tmp_path / "flake"
    flake_dir.mkdir()
    (flake_dir / "flake.nix").write_text(flake, encoding="utf-8")

    df = package_meta.try_scan_package_meta(
        [{"name": "shadow-1.0", "pname": "shadow", "version": "1.0"}],
        flakeref=flake_dir.as_posix(),
        impure=True,
    )

    assert df is not None
    assert df["meta_description"].to_list() == ["shadow description"]
    assert df["meta_cpe"].to_list() == [""]
    assert df["meta_possible_cpes"].to_list() == [""]


def test_package_meta_falls_back_from_empty_legacy_cpe_fields(tmp_path):
    if shutil.which("nix") is None:
        pytest.skip("nix is not available")

    system = package_meta.nix_system()
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
    flake_dir = tmp_path / "flake"
    flake_dir.mkdir()
    (flake_dir / "flake.nix").write_text(flake, encoding="utf-8")

    df = package_meta.try_scan_package_meta(
        [{"name": "shadow-1.0", "pname": "shadow", "version": "1.0"}],
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


def test_package_meta_scans_target_flake_attr_when_name_differs(tmp_path):
    if shutil.which("nix") is None:
        pytest.skip("nix is not available")

    system = package_meta.nix_system()
    flake = """
{
  outputs = { self }:
  let
    system = "__SYSTEM__";
  in
    {
    packages.${system}.doc = (derivation {
      name = "ghaf-docs-0.1.0";
      inherit system;
      builder = "/bin/sh";
      args = [ "-c" "echo docs > $out" ];
    }) // {
      pname = "ghaf-docs";
      version = "0.1.0";
      meta.description = "target flake package attr";
    };
  };
}
""".replace("__SYSTEM__", system)
    flake_dir = tmp_path / "flake"
    flake_dir.mkdir()
    (flake_dir / "flake.nix").write_text(flake, encoding="utf-8")

    components = pd.DataFrame(
        [
            {
                cols.NAME: "ghaf-docs-0.1.0",
                cols.PNAME: "ghaf-docs",
                cols.VERSION: "0.1.0",
                "system": system,
                cols.STORE_PATH: "/nix/store/placeholder.drv",
                cols.OUTPUTS: ["/nix/store/placeholder-out"],
            }
        ]
    )

    for flakeref in (
        f"{flake_dir.as_posix()}#packages.{system}.doc",
        f"{flake_dir.as_posix()}#doc",
    ):
        lookup_keys = package_meta.package_meta_lookup_keys_for_components(
            components,
            target_path="/nix/store/placeholder-out",
            flakeref=flakeref,
        )

        assert lookup_keys[0]["candidateAttrs"] == ["doc"]

        df = package_meta.try_scan_package_meta(
            lookup_keys,
            flakeref=flakeref,
            impure=True,
        )

        assert df is not None
        assert df["meta_description"].to_list() == ["target flake package attr"]
        assert df[cols.NAME].to_list() == ["ghaf-docs-0.1.0"]
        assert df[cols.PNAME].to_list() == ["ghaf-docs"]


def test_package_meta_skips_target_flake_attr_for_versionless_artifact():
    system = "x86_64-linux"
    lookup_keys = package_meta.package_meta_lookup_keys_for_components(
        pd.DataFrame(
            [
                {
                    cols.NAME: "ghaf-host-disko-images",
                    cols.PNAME: "ghaf-host-disko-images",
                    cols.VERSION: "",
                    "system": system,
                    cols.STORE_PATH: "/nix/store/placeholder.drv",
                    cols.OUTPUTS: ["/nix/store/placeholder-out"],
                }
            ]
        ),
        target_path="/nix/store/placeholder-out",
        flakeref=f"/flake#packages.{system}.lenovo-x1-carbon-gen11-debug",
    )

    assert lookup_keys == [
        {
            "name": "ghaf-host-disko-images",
            "pname": "ghaf-host-disko-images",
            "version": "",
            "system": system,
        }
    ]


def test_package_meta_ignores_broken_optional_flake_package_roots(tmp_path):
    if shutil.which("nix") is None:
        pytest.skip("nix is not available")

    system = package_meta.nix_system()
    mk_shadow = """
{ system, description }:
(derivation {
  name = "shadow-1.0";
  inherit system;
  builder = "/bin/sh";
  outputs = [ "out" "dev" ];
  args = [ "-c" "echo out > $out; echo dev > $dev" ];
}) // {
  pname = "shadow";
  version = "1.0";
  meta.description = description;
}
"""
    package_set = """{ system, config ? { } }: {
  shadow = import ./mk-shadow.nix { inherit system; description = "imported"; };
}
"""
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

    package_set_path = tmp_path / "package-set.nix"
    package_set_path.write_text(package_set, encoding="utf-8")
    (tmp_path / "mk-shadow.nix").write_text(mk_shadow, encoding="utf-8")
    flake_dir = tmp_path / "flake"
    flake_dir.mkdir()
    (flake_dir / "flake.nix").write_text(flake, encoding="utf-8")

    df = package_meta.try_scan_package_meta(
        [{"name": "shadow-1.0", "pname": "shadow", "version": "1.0"}],
        flakeref=flake_dir.as_posix(),
        nixpkgs_path=package_set_path,
        impure=True,
    )

    assert df is not None
    assert df["meta_description"].to_list() == ["imported", "imported"]
    assert df[cols.PNAME].to_list() == ["shadow", "shadow"]
    assert df[cols.VERSION].to_list() == ["1.0", "1.0"]


def test_expression_source_cache_requires_expression_identity():
    lookup_keys = [{"name": "pkg-1.0", "pname": "pkg", "version": "1.0"}]
    source = NixpkgsMetaSource(
        method="flakeref-target",
        path="/nix/store/source",
        flakeref="flake#nixosConfigurations.host.pkgs.path",
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
    lookup_keys = [{"name": "pkg-1.0", "pname": "pkg", "version": "1.0"}]

    assert (
        Meta._package_cache_key(
            source,
            lookup_keys,
            flakeref="./flake#default",
        )
        is None
    )

    cache_key = Meta._package_cache_key(
        stable_source,
        lookup_keys,
        flakeref="./flake#default",
    )
    assert cache_key is not None
    assert "path:/nix/store/source?narHash=sha256-test" in cache_key
    assert "#default" not in cache_key
    assert "./flake#default" not in cache_key
    assert (
        meta_module._package_scan_flakeref(
            stable_source,
            "./flake#default",
        )
        == "path:/nix/store/source?narHash=sha256-test#default"
    )


def test_package_metadata_cache_reuses_overlapping_lookup_sets(monkeypatch):
    class NullLock:
        lock_file = "test-lock"

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc, _traceback):
            return False

    class FakeDfCache:
        def __init__(self):
            self.values = {}
            self.set_calls = []

        def get(self, key):
            return self.values.get(key)

        def get_many(self, keys):
            return {key: self.values.get(key) for key in keys}

        def set(self, key, value, ttl=None):
            del ttl
            self.set_calls.append(key)
            self.values[key] = value.copy(deep=True)

    lookup_a = {"name": "alpha-1.0", "pname": "alpha", "version": "1.0"}
    lookup_b = {"name": "beta-1.0", "pname": "beta", "version": "1.0"}
    lookup_c = {"name": "gamma-1.0", "pname": "gamma", "version": "1.0"}
    scan_calls = []

    def fake_scan_package_meta(lookup_keys, **_kwargs):
        scan_calls.append([lookup_key["name"] for lookup_key in lookup_keys])
        return pd.DataFrame(
            [
                {
                    cols.NAME: lookup_key["name"],
                    cols.PNAME: lookup_key["pname"],
                    cols.VERSION: lookup_key["version"],
                }
                for lookup_key in lookup_keys
            ]
        )

    monkeypatch.setattr(
        meta_module,
        "try_scan_package_meta",
        fake_scan_package_meta,
    )
    meta = Meta()
    meta.lock = NullLock()
    meta.cache = FakeDfCache()
    source_alpha = NixpkgsMetaSource(
        method="flakeref-lock",
        path="/nix/store/nixpkgs",
        flakeref_cache_key=(
            "path:/nix/store/source?narHash=sha256-test#packages.x86_64-linux.alpha"
        ),
    )
    source_beta = NixpkgsMetaSource(
        method="flakeref-lock",
        path="/nix/store/nixpkgs",
        flakeref_cache_key=(
            "path:/nix/store/source?narHash=sha256-test#packages.x86_64-linux.beta"
        ),
    )

    meta._scan_package_source(
        source_alpha,
        [lookup_a, lookup_b],
        flakeref="./flake#packages.x86_64-linux.alpha",
    )
    df_second = meta._scan_package_source(
        source_beta,
        [lookup_b, lookup_c],
        flakeref="./flake#packages.x86_64-linux.beta",
    )
    df_third = meta._scan_package_source(
        source_beta,
        [lookup_b, lookup_c],
        flakeref="./flake#packages.x86_64-linux.beta",
    )

    assert scan_calls == [["alpha-1.0", "beta-1.0"], ["gamma-1.0"]]
    assert sorted(df_second[cols.NAME].unique()) == [
        "alpha-1.0",
        "beta-1.0",
        "gamma-1.0",
    ]
    assert sorted(df_third[cols.NAME].unique()) == [
        "alpha-1.0",
        "beta-1.0",
        "gamma-1.0",
    ]
    assert len(meta.cache.set_calls) == 5
    assert not any(":lookup:" in key for key in meta.cache.set_calls)
    assert sum(":lookup-index" in key for key in meta.cache.set_calls) == 2


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
