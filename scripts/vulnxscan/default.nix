# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  perSystem = {
    pkgs,
    self',
    ...
  }: {
    packages = let
      pythonPackages = pkgs.python3Packages;
    in {
      vulnix =
        pkgs
        .vulnix
        .overrideAttrs (
          _old: rec {
            # We use vulnix from 'https://github.com/henrirosten/vulnix' to get
            # vulnix support for runtime-only scan ('-C' command-line option)
            # which is currently not available in released version of vulnix.
            src = pkgs.fetchFromGitHub {
              owner = "henrirosten";
              repo = "vulnix";
              rev = "ad28b2924027a44a9b81493a0f9de1b0e8641005";
              sha256 = "sha256-KXvmnaMjv//zd4aSwu4qmbon1Iyzdod6CPms7LIxeVU=";
            };
            version = "1.10.2.dev0";
            name = "vulnix-${version}";
          }
        );

      vulnxscan = let
        inherit (self'.packages) sbomnix repology_cli requests-ratelimiter vulnix;
      in
        pythonPackages.buildPythonPackage rec {
          pname = "vulnxscan";
          version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../../VERSION);
          format = "setuptools";

          src = ../../.;

          makeWrapperArgs = [
            "--prefix PATH : ${pkgs.lib.makeBinPath [sbomnix repology_cli pkgs.grype pkgs.nix vulnix]}"
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
            install -vD scripts/vulnxscan/vulnxscan.py $out/bin/vulnxscan.py
          '';

          pythonImportsCheck = ["sbomnix"];

          meta = {
            # TODO add more meta attributes
            mainProgram = "vulnxscan.py";
          };
        };
    };
  };
}
