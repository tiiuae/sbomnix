# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

{ nixpkgs ? <nixpkgs>
, pkgs ? import nixpkgs {}
, pythonPackages ? pkgs.python3Packages
, lib ? pkgs.lib
}:

pythonPackages.buildPythonPackage rec {
  version = "1.0.5";
  pname = "nix-visualize";

  src = pkgs.fetchFromGitHub {
    owner = "henrirosten";
    repo = pname;
    rev = "5b451b5ab7a199ecdd94a2c1fa5aa92120a89941";
    sha256 = "sha256-wRhgq5aljOa1uyIpaJSH7XgIrBgOm9LdHnSUKlholdU=";
  };
  propagatedBuildInputs = with pythonPackages; [
    matplotlib
    networkx
    pygraphviz
    pandas
  ];
}
