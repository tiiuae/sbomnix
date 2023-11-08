# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
# TODO: this should be in nixpkgs
{
  nixpkgs ? <nixpkgs>,
  pkgs ? import nixpkgs {},
  pythonPackages ? pkgs.python3Packages,
  lib ? pkgs.lib,
}:
pythonPackages.buildPythonPackage rec {
  version = "2.10.0";
  pname = "pyrate-limiter";
  format = "pyproject";

  src = pkgs.fetchFromGitHub {
    owner = "vutran1710";
    repo = "PyrateLimiter";
    rev = "v${version}";
    hash = "sha256-CPusPeyTS+QyWiMHsU0ii9ZxPuizsqv0wQy3uicrDw0=";
  };

  propagatedBuildInputs = with pythonPackages; [
    poetry-core
  ];
}
