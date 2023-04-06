# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages,
  vulnix ? import ./vulnix.nix { nixpkgs=pkgs.path; pkgs=pkgs; },
}:

pythonPackages.buildPythonPackage rec {
  pname = "vulnxscan";
  version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../../VERSION);
  format = "setuptools";

  src = ../../.;
  sbomnix = import ../../default.nix { pkgs=pkgs; };
  makeWrapperArgs = [
    "--prefix PATH : ${pkgs.lib.makeBinPath [ sbomnix pkgs.grype vulnix ]}"
  ];

  propagatedBuildInputs = [ 
    sbomnix
    pythonPackages.requests
  ];

  postInstall = ''
    install -vD scripts/vulnxscan/vulnxscan.py $out/bin/vulnxscan.py
  '';

  pythonImportsCheck = [ "sbomnix" ];
}
