# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  perSystem =
    {
      pkgs,
      lib,
      ...
    }:
    let
      python = pkgs.python3.override {
        self = pkgs.python3;
        packageOverrides = _final: prev: {
          pyrate-limiter = prev.pyrate-limiter.overridePythonAttrs (oldAttrs: rec {
            # https://github.com/JWCook/requests-ratelimiter/issues/78
            version = "2.10.0";
            src = pkgs.fetchFromGitHub {
              inherit (oldAttrs.src) owner repo;
              tag = "v${version}";
              hash = "sha256-CPusPeyTS+QyWiMHsU0ii9ZxPuizsqv0wQy3uicrDw0=";
            };
            doCheck = false;
          });
        };
      };
      pp = python.pkgs;
      prefix_path = with pkgs; [
        git
        graphviz
        grype
        nix
        nix-visualize
        vulnix
      ];
    in
    {
      packages = rec {
        default = sbomnix;

        sbomnix = pp.buildPythonPackage rec {
          pname = "sbomnix";
          version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../VERSION);
          format = "setuptools";

          src = lib.cleanSource ../.;

          nativeCheckInputs =
            with pp;
            [
              jsonschema
              pytest
              pytest-xdist
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

          pythonImportsCheck = [ "sbomnix" ];

          makeWrapperArgs = [
            "--prefix PATH : ${lib.makeBinPath prefix_path}"
          ];
        };
      };
    };
}
