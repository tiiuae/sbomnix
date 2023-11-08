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
  version = "0.4.0";
  pname = "requests-ratelimiter";
  format = "pyproject";

  src = pkgs.fetchFromGitHub {
    owner = "JWCook";
    repo = pname;
    rev = "v${version}";
    hash = "sha256-F9bfcwijyyKzlFKBJAC/5ETc4/hZpPhm2Flckku2z6M=";
  };

  pyrate-limiter = import ./pyrate-limiter.nix {inherit pkgs;};

  propagatedBuildInputs = with pythonPackages; [
    poetry-core
    pyrate-limiter
    requests
  ];
}
