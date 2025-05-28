# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{ inputs, ... }:
{
  imports = with inputs; [
    flake-root.flakeModule
    treefmt-nix.flakeModule
  ];
  perSystem =
    {
      config,
      pkgs,
      ...
    }:
    {
      treefmt.config = {
        package = pkgs.treefmt;
        inherit (config.flake-root) projectRootFile;

        programs = {
          deadnix.enable = true; # removes dead nix code https://github.com/astro/deadnix
          isort.enable = true; # sort python imports https://github.com/PyCQA/isort
          shellcheck.enable = true; # lints shell scripts https://github.com/koalaman/shellcheck
          nixfmt.enable = true; # nix formatter https://github.com/NixOS/nixfmt
          ruff-check.enable = true; # lints python https://github.com/astral-sh/ruff
          ruff-format.enable = true; # format python https://github.com/astral-sh/ruff
          statix.enable = true; # prevents use of nix anti-patterns https://github.com/nerdypepper/statix
          actionlint.enable = true; # lints github actions
        };
      };

      # configures treefmt as the program to use when invoke `nix fmt`
      formatter = config.treefmt.build.wrapper;
    };
}
