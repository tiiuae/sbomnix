# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  perSystem =
    {
      pkgs,
      lib,
      config,
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
      check_inputs = with pp; [
        jsonschema
        pytest
        pytest-xdist
      ];
      build_inputs = with pp; [
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
        setuptools
        tabulate
      ];
    in
    {
      packages = rec {
        default = sbomnix;
        sbomnix = pp.buildPythonPackage {
          pname = "sbomnix";
          version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../VERSION);
          format = "setuptools";
          src = lib.cleanSource ../.;
          nativeCheckInputs = check_inputs;
          propagatedBuildInputs = build_inputs;
          pythonImportsCheck = [ "sbomnix" ];
          makeWrapperArgs = [
            "--prefix PATH : ${lib.makeBinPath prefix_path}"
          ];
        };
      };
      devShells.default = pkgs.mkShell {
        name = "sbomnix-devshell";
        packages = [
          pkgs.python3.pkgs.pylint # for running pylint manually in devshell
          pkgs.ruff # for running ruff manually in devshell
          pkgs.isort # for running isort manually in devshell
          check_inputs
          build_inputs
        ];
        # Add the repo root to PYTHONPATH, so invoking entrypoints (and them being
        # able to find the python packages in the repo) becomes possible.
        # `pytest.ini` already sets this for invoking `pytest`
        # (cascading down to the processes it spawns), but this is for the developer
        # invoking entrypoints from inside the devshell.
        shellHook = ''
          ${config.pre-commit.installationScript}
          echo 1>&2 "Welcome to the development shell!"
          export PATH=${lib.makeBinPath prefix_path}:$PATH
          export PYTHONPATH="$PYTHONPATH:$(pwd)/src"
          # https://github.com/NixOS/nix/issues/1009:
          export TMPDIR="/tmp"
        '';
      };
    };
}
