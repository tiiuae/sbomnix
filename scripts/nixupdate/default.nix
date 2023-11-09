# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{ inputs, ... }: {
  perSystem = {
    pkgs,
    self',
    ...
  }: let
    pythonPackages = pkgs.python3Packages;
  in {
    packages = {

      nix_visualize = (import "${inputs.nix-visualize}/default.nix") { inherit pkgs; };

      nixupdate = let
        inherit
          (self'.packages)
          repology_cli
          nix_visualize
          requests-ratelimiter
          ;
      in
        pythonPackages.buildPythonPackage rec {
          pname = "nixupdate";
          version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../../VERSION);
          format = "setuptools";

          src = ../../.;

          makeWrapperArgs = [
            "--prefix PATH : ${pkgs.lib.makeBinPath [repology_cli nix_visualize]}"
          ];

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
            install -vD scripts/nixupdate/nix_outdated.py $out/bin/nix_outdated.py
          '';

          pythonImportsCheck = ["sbomnix"];
        };
    };
    apps = {
      nix_outdated = {
        type = "app";
        program = "${self'.packages.nixupdate}/bin/nix_outdated.py";
      };
    };
  };
}
