# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{inputs, ...}: {
  imports = with inputs; [
    flake-root.flakeModule
    treefmt-nix.flakeModule
  ];
  perSystem = {
    config,
    pkgs,
    ...
  }: {
    treefmt.config = {
      package = pkgs.treefmt;
      inherit (config.flake-root) projectRootFile;

      programs = {
        alejandra.enable = true; # nix formatter https://github.com/kamadorueda/alejandra
        black.enable = true; # lints python https://github.com/psf/black
        deadnix.enable = true; # removes dead nix code https://github.com/astro/deadnix
        shellcheck.enable = true; # lints shell scripts https://github.com/koalaman/shellcheck
        statix.enable = true; # prevents use of nix anti-patterns https://github.com/nerdypepper/statix
      };
    };

    # configures treefmt as the program to use when invoke `nix fmt`
    formatter = config.treefmt.build.wrapper;
  };
}
