# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages,
}:

pythonPackages.buildPythonPackage rec {
  pname = "sbomnix";
  version = pkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);
  format = "setuptools";

  src = ./.;
  makeWrapperArgs = [
    "--prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.nix pkgs.graphviz ]}"
  ];

  propagatedBuildInputs = [ 
    pkgs.reuse
    pythonPackages.colorlog
    pythonPackages.graphviz
    pythonPackages.numpy
    pythonPackages.packageurl-python
    pythonPackages.pandas
    pythonPackages.requests
    pythonPackages.tabulate
  ];
  pythonImportsCheck = [ "sbomnix" ];
}