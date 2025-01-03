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
    prefix_path = with pkgs; [
      git
      graphviz
      grype
      nix
      nix-visualize
      vulnix
    ];
  in {
    packages = rec {
      default = sbomnix;

      sbomnix = pp.buildPythonPackage rec {
        pname = "sbomnix";
        version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../VERSION);
        format = "setuptools";

        src = lib.cleanSource ../.;

        nativeCheckInputs = with pp;
          [
            jsonschema
            pytest
          ]
          ++ prefix_path;

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
          "--prefix PATH : ${lib.makeBinPath prefix_path}"
        ];
      };
    };
  };
}
