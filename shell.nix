# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages,
}:
pkgs.mkShell rec {
  name = "sbomnix-dev-shell";

  nixupdate = import ./scripts/nixupdate/nixupdate.nix {inherit pkgs;};
  nix_visualize = import ./scripts/nixupdate/nix-visualize.nix {inherit pkgs;};
  requests-ratelimiter = import ./scripts/repology/requests-ratelimiter.nix {inherit pkgs;};
  repology_cli = import ./scripts/repology/repology_cli.nix {inherit pkgs;};
  vulnix = import ./scripts/vulnxscan/vulnix.nix {
    nixpkgs = pkgs.path;
    inherit pkgs;
  };
  vulnxscan = import ./scripts/vulnxscan/vulnxscan.nix {inherit pkgs;};

  buildInputs = [
    nixupdate
    nix_visualize
    requests-ratelimiter
    repology_cli
    vulnix
    vulnxscan
    pkgs.coreutils
    pkgs.curl
    pkgs.gnugrep
    pkgs.gnused
    pkgs.graphviz
    pkgs.grype
    pkgs.gzip
    pkgs.nix
    pkgs.reuse
    pythonPackages.beautifulsoup4
    pythonPackages.colorlog
    pythonPackages.graphviz
    pythonPackages.numpy
    pythonPackages.packageurl-python
    pythonPackages.packaging
    pythonPackages.pandas
    pythonPackages.requests
    pythonPackages.requests-cache
    pythonPackages.tabulate
    pythonPackages.venvShellHook
    pythonPackages.wheel
  ];
  venvDir = "venv";
  postShellHook = ''
    source $PWD/scripts/env.sh

    # https://github.com/NixOS/nix/issues/1009:
    export TMPDIR="/tmp"

    # Enter python development environment
    make install-dev
  '';
}
