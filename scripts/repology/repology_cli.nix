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
  sbomnix = import ../../default.nix { pkgs=pkgs; };
  makeWrapperArgs = [
    "--prefix PATH : ${pkgs.lib.makeBinPath [ sbomnix ]}"
  ];
  
  requests-ratelimiter = import ./requests-ratelimiter.nix { pkgs=pkgs; };

  propagatedBuildInputs = [ 
    sbomnix
    requests-ratelimiter
    pythonPackages.beautifulsoup4
    pythonPackages.requests
    pythonPackages.requests-cache
    pythonPackages.packaging
  ];

  postInstall = ''
    install -vD scripts/repology/repology_cli.py $out/bin/repology_cli.py
    install -vD scripts/repology/repology_cve.py $out/bin/repology_cve.py
  '';

  pythonImportsCheck = [ "sbomnix" ];
}
