# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages,
}:

pythonPackages.buildPythonPackage rec {
  pname = "nix_outdated";
  version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../../VERSION);
  format = "setuptools";

  src = ../../.;
  sbomnix = import ../../default.nix { pkgs=pkgs; };
  repology_cli = import ../repology/repology_cli.nix { pkgs=pkgs; };
  nix_visualize = import ../nixupdate/nix-visualize.nix { pkgs=pkgs; };
  makeWrapperArgs = [
    "--prefix PATH : ${pkgs.lib.makeBinPath [ sbomnix repology_cli nix_visualize ]}"
  ];

  propagatedBuildInputs = [ 
    sbomnix
  ];

  postInstall = ''
    install -vD scripts/nixupdate/nix_outdated.py $out/bin/nix_outdated.py
  '';

  pythonImportsCheck = [ "sbomnix" ];
}
