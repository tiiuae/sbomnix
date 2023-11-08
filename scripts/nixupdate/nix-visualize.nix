# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  nixpkgs ? <nixpkgs>,
  pkgs ? import nixpkgs {},
  pythonPackages ? pkgs.python3Packages,
}:
pythonPackages.buildPythonPackage rec {
  version = "1.0.5";
  pname = "nix-visualize";

  src = pkgs.fetchFromGitHub {
    owner = "henrirosten";
    repo = pname;
    rev = "7fedf92eacffd5c42c50f7fec72f61a377c9ccf3";
    hash = "sha256-Z1r8XHszoUnQinl63yXvQG6Czp5HnYNG37AY+EEiT4w=";
  };
  propagatedBuildInputs = with pythonPackages; [
    matplotlib
    networkx
    pygraphviz
    pandas
  ];
}
