# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  perSystem = {
    pkgs,
    lib,
    ...
  }: let
    pp = pkgs.python3Packages;
  in {
    packages = rec {
      default = sbomnix;

      sbomnix = pp.buildPythonPackage rec {
        pname = "sbomnix";
        version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../VERSION);
        format = "setuptools";

        src = lib.cleanSource ../.;

        propagatedBuildInputs = with pp; [
          beautifulsoup4
          colorlog
          dfdiskcache
          filelock
          graphviz
          numpy
          packageurl-python
          packaging
          pandas
          pyrate-limiter
          reuse
          requests
          requests-cache
          requests-ratelimiter
          tabulate
        ];

        pythonImportsCheck = ["sbomnix"];

        makeWrapperArgs = [
          "--prefix PATH : ${lib.makeBinPath (with pkgs; [
            git
            nix
            graphviz
            nix-visualize
            vulnix
            grype
          ])}"
        ];
      };
      # a python with all python packages imported by sbomnix itself
      python = pkgs.python3.withPackages (
        ps: (with ps; [
          beautifulsoup4
          colorlog
          dfdiskcache
          filelock
          graphviz
          numpy
          packageurl-python
          packaging
          pandas
          reuse
          requests
          requests-cache
          requests-ratelimiter
          setuptools
          tabulate
          venvShellHook

          # dev dependencies
          jsonschema
          pytest
        ])
      );
    };
  };
}
