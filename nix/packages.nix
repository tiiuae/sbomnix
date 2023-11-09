# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{inputs, ...}: {
  perSystem = {
    pkgs,
    lib,
    ...
  }: let
    pp = pkgs.python3Packages;

    # We use vulnix from 'https://github.com/henrirosten/vulnix' to get
    # vulnix support for runtime-only scan ('-C' command-line option)
    # which is currently not available in released version of vulnix.
    vulnix = (import inputs.vulnix) {
      inherit (inputs) nixpkgs; # required but not used as we provide pkgs
      inherit pkgs lib;
    };

    nix-visualize = (import inputs.nix-visualize) {inherit pkgs;};

    pyrate-limiter = pp.buildPythonPackage rec {
      version = "2.10.0";
      pname = "pyrate-limiter";
      format = "pyproject";

      src = pkgs.fetchFromGitHub {
        owner = "vutran1710";
        repo = "PyrateLimiter";
        rev = "v${version}";
        hash = "sha256-CPusPeyTS+QyWiMHsU0ii9ZxPuizsqv0wQy3uicrDw0=";
      };

      propagatedBuildInputs = [
        pp.poetry-core
      ];
    };

    requests-ratelimiter = pp.buildPythonPackage rec {
      version = "0.4.0";
      pname = "requests-ratelimiter";
      format = "pyproject";

      src = pkgs.fetchFromGitHub {
        owner = "JWCook";
        repo = pname;
        rev = "v${version}";
        hash = "sha256-F9bfcwijyyKzlFKBJAC/5ETc4/hZpPhm2Flckku2z6M=";
      };

      propagatedBuildInputs = [pyrate-limiter pp.requests];
    };
  in {
    packages = rec {
      default = sbomnix;

      sbomnix = pp.buildPythonPackage rec {
        pname = "sbomnix";
        version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../VERSION);
        format = "setuptools";

        src = lib.cleanSource ../.;

        propagatedBuildInputs = lib.flatten [
          [
            pyrate-limiter
            requests-ratelimiter
          ]
          [pkgs.reuse]
          (with pp; [
            beautifulsoup4
            colorlog
            graphviz
            numpy
            packageurl-python
            packaging
            pandas
            requests
            requests-cache
            tabulate
          ])
        ];

        pythonImportsCheck = ["sbomnix"];

        postInstall = ''

          wrapProgram $out/bin/sbomnix \
                        --prefix PATH : ${lib.makeBinPath [pkgs.nix pkgs.graphviz]}

          wrapProgram $out/bin/nixgraph \
                        --prefix PATH : ${lib.makeBinPath [pkgs.nix pkgs.graphviz]}

          wrapProgram $out/bin/nix_outdated \
              --prefix PATH : ${lib.makeBinPath [nix-visualize]}

          wrapProgram $out/bin/vulnxscan \
              --prefix PATH : ${lib.makeBinPath [pkgs.grype pkgs.nix vulnix]}

        '';
      };
    };
  };
}
