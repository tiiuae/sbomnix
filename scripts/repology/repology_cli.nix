# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages,
}:

pythonPackages.buildPythonPackage rec {
  pname = "repology_cli";
  version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../../VERSION);
  format = "setuptools";

  src = ../../.;

  requests-ratelimiter = import ./requests-ratelimiter.nix { pkgs=pkgs; };

  propagatedBuildInputs = [ 
    pkgs.reuse
    requests-ratelimiter
    pythonPackages.beautifulsoup4
    pythonPackages.colorlog
    pythonPackages.graphviz
    pythonPackages.numpy
    pythonPackages.packageurl-python
    pythonPackages.packaging
    pythonPackages.pandas
    pythonPackages.tabulate
    pythonPackages.requests
    pythonPackages.requests-cache
  ];

  postInstall = ''
    install -vD scripts/repology/repology_cli.py $out/bin/repology_cli.py
    install -vD scripts/repology/repology_cve.py $out/bin/repology_cve.py
  '';

  pythonImportsCheck = [ "sbomnix" ];
}
