# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  perSystem = {
    pkgs,
    self',
    ...
  }: {
    devShells.default = pkgs.mkShell rec {
      name = "sbomnix-dev-shell";

      packages =
        (with pkgs; [
          coreutils
          curl
          gnugrep
          gnused
          graphviz
          grype
          gzip
          nix
          black
          reuse
        ])
        ++ (with self'.packages; [
          nix-visualize
          python # that python with all sbomnix [dev-]dependencies
          vulnix
        ]);

      # Add the repo root to PYTHONPATH, so invoking entrypoints (and them being
      # able to find the python packages in the repo) becomes possible.
      # `pytest.ini` already sets this for invoking `pytest`
      # (cascading down to the processes it spawns), but this is for the developer
      # invoking entrypoints from inside the devshell.
      shellHook = ''
        export PYTHONPATH="$PYTHONPATH:$(pwd)/src"
      '';
    };
  };
}
