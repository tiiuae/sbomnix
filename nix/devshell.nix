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
          black
          coreutils
          csvkit
          curl
          gnugrep
          gnused
          graphviz
          grype
          gzip
          nix
          nix-visualize
          pylint
          reuse
          vulnix
        ])
        ++ (with self'.packages; [
          python # that python with all sbomnix [dev-]dependencies
        ]);

      # Add the repo root to PYTHONPATH, so invoking entrypoints (and them being
      # able to find the python packages in the repo) becomes possible.
      # `pytest.ini` already sets this for invoking `pytest`
      # (cascading down to the processes it spawns), but this is for the developer
      # invoking entrypoints from inside the devshell.
      shellHook = ''
        export PYTHONPATH="$PYTHONPATH:$(pwd)/src"
        # https://github.com/NixOS/nix/issues/1009:
        export TMPDIR="/tmp"
      '';
    };
  };
}
