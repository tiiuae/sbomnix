# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages
}:

pythonPackages.buildPythonPackage rec {
  pname = "sbomnix";
  version = "1.2.0";
  format = "setuptools";

  src = ./.;

  postPatch = ''
    substituteInPlace setup.py \
      --replace "use_scm_version=True," "version='${version}'," \
      --replace "setup_requires=['setuptools_scm']," "setup_requires=[],"
  '';

  propagatedBuildInputs = [ 
    pkgs.reuse
    pythonPackages.numpy
    pythonPackages.pandas
    pythonPackages.colorlog
    pythonPackages.tabulate
    pythonPackages.wheel
    pythonPackages.packageurl-python
    pythonPackages.requests
    pythonPackages.graphviz
  ];

  pythonImportsCheck = [ "sbomnix" ];
}
