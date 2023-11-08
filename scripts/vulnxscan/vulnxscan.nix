# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages,
  vulnix ?
    import ./vulnix.nix {
      nixpkgs = pkgs.path;
      inherit pkgs;
    },
}:
pythonPackages.buildPythonPackage rec {
  pname = "vulnxscan";
  version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../../VERSION);
  format = "setuptools";

  src = ../../.;
  sbomnix = import ../../default.nix {inherit pkgs;};
  repology_cli = import ../repology/repology_cli.nix {inherit pkgs;};
  makeWrapperArgs = [
    "--prefix PATH : ${pkgs.lib.makeBinPath [sbomnix repology_cli pkgs.grype pkgs.nix vulnix]}"
  ];

  requests-ratelimiter = import ../repology/requests-ratelimiter.nix {inherit pkgs;};

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
    install -vD scripts/vulnxscan/vulnxscan.py $out/bin/vulnxscan.py
  '';

  pythonImportsCheck = ["sbomnix"];
}
