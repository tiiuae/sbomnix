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
  in {
    packages = rec {
      default = sbomnix;

      # requests-ratelimiter currently does not support pyrate-limiter v3,
      # see: https://github.com/JWCook/requests-ratelimiter/issues/78
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

      # requests-ratelimiter currently does not support pyrate-limiter v3,
      # see: https://github.com/JWCook/requests-ratelimiter/issues/78
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

      # reuse is imported by sbomdb.py. For this to work with a python.withPackages,
      # reuse needs to be a buildPythonPackage, not buildPythonApplication.
      # Sent to nixpkgs in https://github.com/NixOS/nixpkgs/pull/267527
      #
      # Also note their library docstring:
      # > reuse is a tool for compliance with the REUSE recommendations.
      # > Although the API is documented, it is **NOT** guaranteed stable
      # > between minor or even patch releases.
      # > The semantic versioning of this program pertains exclusively to the
      # > reuse CLI command. If you want to use reuse as a Python library, you
      # > should pin reuse to an exact version.
      # … so it might be a good idea to pin this anyways.
      reuse = pp.buildPythonPackage rec {
        pname = "reuse";
        version = "2.1.0";
        format = "pyproject";

        src = pkgs.fetchFromGitHub {
          owner = "fsfe";
          repo = "reuse-tool";
          rev = "refs/tags/v${version}";
          hash = "sha256-MEQiuBxe/ctHlAnmLhQY4QH62uAcHb7CGfZz+iZCRSk=";
        };

        nativeBuildInputs = with pp; [
          poetry-core
        ];

        propagatedBuildInputs = with pp; [
          binaryornot
          boolean-py
          debian
          jinja2
          license-expression
        ];

        nativeCheckInputs = with pp; [pytestCheckHook];

        disabledTestPaths = [
          # pytest wants to execute the actual source files for some reason, which fails with ImportPathMismatchError()
          "src/reuse"
        ];
      };

      # We use vulnix from 'https://github.com/henrirosten/vulnix' to get
      # vulnix support for runtime-only scan ('-C' command-line option)
      # which is currently not available in released version of vulnix.
      # Pending https://github.com/nix-community/vulnix/pull/80
      vulnix = (import inputs.vulnix) {
        inherit (inputs) nixpkgs; # required but not used as we provide pkgs
        inherit pkgs lib;
      };

      nix-visualize = (import inputs.nix-visualize) {inherit pkgs;};

      sbomnix = pp.buildPythonPackage rec {
        pname = "sbomnix";
        version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../VERSION);
        format = "setuptools";

        src = lib.cleanSource ../.;

        propagatedBuildInputs =
          [
            pyrate-limiter
            requests-ratelimiter
            reuse
          ]
          ++ (with pp; [
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
          ]);

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
      # a python with all python packages imported by sbomnix itself
      python = pkgs.python3.withPackages (ps:
        (with ps; [
          beautifulsoup4
          colorlog
          graphviz
          numpy
          packageurl-python
          packaging
          pandas
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
        ++ [reuse]);
    };
  };
}
