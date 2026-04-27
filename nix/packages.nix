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
      pp = pkgs.python3.pkgs;
      prefix_path = with pkgs; [
        git
        graphviz
        grype
        nix
        nix-visualize
        vulnix
      ];
      check_inputs = with pp; [
        hypothesis
        jsonschema
        pytest
        pytest-cov
        pytest-xdist
      ];
      build_system = with pp; [ setuptools ];
      build_inputs = with pp; [
        beautifulsoup4
        colorlog
        dfdiskcache
        filelock
        graphviz
        pp."license-expression"
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
    in
    {
      packages = rec {
        default = sbomnix;
        sbomnix = pp.buildPythonPackage {
          pname = "sbomnix";
          version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../VERSION);
          pyproject = true;
          src = lib.cleanSource ../.;
          build-system = build_system;
          nativeCheckInputs = check_inputs;
          dependencies = build_inputs;
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
          pkgs.pyright # for running pyright manually in devshell
          pkgs.ruff # for running ruff manually in devshell
          pkgs.isort # for running isort manually in devshell
        ]
        ++ check_inputs
        ++ build_system
        ++ build_inputs;
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
