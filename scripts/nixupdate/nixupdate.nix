# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages,
}:

pythonPackages.buildPythonPackage rec {
  pname = "nixupdate";
  version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../../VERSION);
  format = "setuptools";

  src = ../../.;
  repology_cli = import ../repology/repology_cli.nix { pkgs=pkgs; };
  nix_visualize = import ./nix-visualize.nix { pkgs=pkgs; };
  makeWrapperArgs = [
    "--prefix PATH : ${pkgs.lib.makeBinPath [ repology_cli nix_visualize ]}"
  ];

  requests-ratelimiter = import ../repology/requests-ratelimiter.nix { pkgs=pkgs; };

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
    install -vD scripts/nixupdate/nix_outdated.py $out/bin/nix_outdated.py
  '';

  pythonImportsCheck = [ "sbomnix" ];
}
