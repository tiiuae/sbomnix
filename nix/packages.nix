# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{ self, ... }:
{
  perSystem =
    {
      pkgs,
      lib,
      config,
      self',
      ...
    }:
    let
      pp = pkgs.python3.pkgs;
      baseVersion = pkgs.lib.removeSuffix "\n" (builtins.readFile ../VERSION);
      # Append git state so local builds are distinguishable from release
      # artifacts. shortRev is set on a clean tree; dirtyShortRev (Nix >= 2.14)
      # is set when the working tree has uncommitted changes.
      gitSuffix =
        if self ? shortRev then
          "+g${self.shortRev}"
        else if self ? dirtyShortRev then
          "+g${self.dirtyShortRev}"
        else
          "";
      # Thin wrapper that calls a module entry point via the ambient python3.
      # PYTHONPATH (set in shellHook) resolves to the local src/, so edits are
      # picked up without reinstalling.
      mkDevEntry =
        name: module:
        pkgs.writeShellScriptBin name ''
          exec python3 -c "import sys; sys.argv[0]='${name}'; from ${module} import main; main()" "$@"
        '';
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
          version = "${baseVersion}${gitSuffix}";
          pyproject = true;
          src = lib.cleanSource ../.;
          postPatch = ''
            printf '%s' "${baseVersion}${gitSuffix}" > VERSION
          '';
          build-system = build_system;
          nativeCheckInputs = check_inputs;
          dependencies = build_inputs;
          pythonImportsCheck = [ "sbomnix" ];
          makeWrapperArgs = [
            "--prefix PATH : ${lib.makeBinPath prefix_path}"
          ];
        };
      };
      checks =
        # Force a build of all packages during a `nix flake check`.
        with lib; mapAttrs' (n: nameValuePair "package-${n}") self'.packages;
      devShells.default = pkgs.mkShell {
        name = "sbomnix-devshell";
        packages = [
          pkgs.pyright # for running pyright manually in devshell
          pkgs.ruff # for running ruff manually in devshell
        ]
        ++ check_inputs
        ++ build_system
        ++ build_inputs
        ++ [
          (mkDevEntry "sbomnix" "sbomnix.main")
          (mkDevEntry "nixgraph" "nixgraph.main")
          (mkDevEntry "nixmeta" "nixmeta.main")
          (mkDevEntry "nix_outdated" "nixupdate.nix_outdated")
          (mkDevEntry "vulnxscan" "vulnxscan.vulnxscan_cli")
          (mkDevEntry "repology_cli" "repology.repology_cli")
          (mkDevEntry "repology_cve" "repology.repology_cve")
          (mkDevEntry "provenance" "provenance.main")
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
