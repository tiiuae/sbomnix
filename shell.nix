# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
  pythonPackages ? pkgs.python3Packages,
}:

pkgs.mkShell rec {
  name = "sbomnix-dev-shell";

  cve-bin-tool = import ./scripts/vulnxscan/cve-bin-tool.nix { pkgs=pkgs; };
  nixupdate = import ./scripts/nixupdate/nixupdate.nix { pkgs=pkgs; };
  nix_visualize = import ./scripts/nixupdate/nix-visualize.nix { pkgs=pkgs; };
  requests-ratelimiter = import ./scripts/repology/requests-ratelimiter.nix { pkgs=pkgs; };
  repology_cli = import ./scripts/repology/repology_cli.nix { pkgs=pkgs; };
  vulnix = import ./scripts/vulnxscan/vulnix.nix { nixpkgs=pkgs.path; pkgs=pkgs; };
  vulnxscan = import ./scripts/vulnxscan/vulnxscan.nix { pkgs=pkgs; };

  buildInputs = [ 
    cve-bin-tool
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
