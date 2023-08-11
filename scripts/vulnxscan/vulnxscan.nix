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
  cve-bin-tool = import ./cve-bin-tool.nix { pkgs=pkgs; };
  makeWrapperArgs = [
    "--prefix PATH : ${pkgs.lib.makeBinPath [ sbomnix pkgs.grype pkgs.nix vulnix cve-bin-tool ]}"
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
