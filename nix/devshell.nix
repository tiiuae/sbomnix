# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  perSystem = {
    pkgs,
    self',
    inputs',
    ...
  }: {
    devShells.default = let
      pythonPackages = pkgs.python3Packages;
    in
      pkgs.mkShell rec {
        name = "sbomnix-dev-shell";

        buildInputs = [
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
          inputs'.nix-fast-build.packages.default
        ];
        venvDir = "venv";
        postShellHook = ''
          source $PWD/scripts/env.sh

          # https://github.com/NixOS/nix/issues/1009:
          export TMPDIR="/tmp"

          # Enter python development environment
          make install-dev
        '';
      };
  };
}
