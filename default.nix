# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages,
  vulnix ? import ./scripts/vulnxscan/vulnix.nix { nixpkgs=pkgs.path; pkgs=pkgs; },
}:

pythonPackages.buildPythonPackage rec {
  pname = "sbomnix";
  version = "1.4.3";
  format = "setuptools";

  src = ./.;

  postPatch = ''
    substituteInPlace setup.py \
      --replace "use_scm_version=True," "version='${version}'," \
      --replace "setup_requires=['setuptools_scm']," "setup_requires=[],"
  '';

  propagatedBuildInputs = [ 
    pkgs.reuse
    pkgs.grype
    pkgs.curl
    vulnix
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