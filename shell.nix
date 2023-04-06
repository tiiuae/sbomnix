# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages,
}:

pkgs.mkShell rec {
  name = "sbomnix-dev-shell";

  sbomnix = import ./default.nix { pkgs=pkgs; };
  vulnxscan = import ./scripts/vulnxscan/vulnxscan.nix { pkgs=pkgs; };
  repology_cli = import ./scripts/repology/repology_cli.nix { pkgs=pkgs; };
  nix_outdated = import ./scripts/nixupdate/nix_outdated.nix { pkgs=pkgs; };

  buildInputs = [ 
    sbomnix
    vulnxscan
    repology_cli
    nix_outdated
    pythonPackages.wheel
    pythonPackages.venvShellHook
  ];
  venvDir = "venv";
  postShellHook = ''
    # https://github.com/NixOS/nix/issues/1009:
    export TMPDIR="/tmp"
    
    # Enter python development environment
    make install-dev
  '';
}
