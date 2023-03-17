# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages,
  vulnix ? import ./scripts/vulnxscan/vulnix.nix { nixpkgs=pkgs.path; pkgs=pkgs; },
  nix-visualize ? import ./scripts/nixupdate/nix-visualize.nix { nixpkgs=pkgs.path; pkgs=pkgs; },
}:

pkgs.mkShell {
  name = "sbomnix-dev-shell";

  buildInputs = [ 
    pkgs.reuse
    pkgs.grype
    pkgs.curl
    vulnix
    nix-visualize
    pythonPackages.pip
    pythonPackages.numpy
    pythonPackages.pandas
    pythonPackages.colorlog
    pythonPackages.tabulate
    pythonPackages.wheel
    pythonPackages.packageurl-python
    pythonPackages.graphviz
    pythonPackages.pycodestyle
    pythonPackages.pylint
    pythonPackages.black
    pythonPackages.pytest
    pythonPackages.jsonschema
    pythonPackages.requests
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
