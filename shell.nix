# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages
}:

pkgs.mkShell {
  name = "sbomnix-dev-shell";

  buildInputs = [ 
    pkgs.reuse
    pythonPackages.numpy
    pythonPackages.pandas
    pythonPackages.colorlog
    pythonPackages.tabulate
    pythonPackages.wheel
    pythonPackages.packageurl-python
    pythonPackages.graphviz
    pythonPackages.pycodestyle
    pythonPackages.pylint
    pythonPackages.black
    pythonPackages.pytest
    pythonPackages.jsonschema
    pythonPackages.venvShellHook
  ];
  venvDir = "venv";
  postShellHook = ''
    make install-dev
  '';
}
