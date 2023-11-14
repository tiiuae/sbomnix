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
    };
  };
}
