# SPDX-FileCopyrightText: 2025-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
{ inputs, ... }:
{
  imports = with inputs; [
    git-hooks-nix.flakeModule
  ];
  perSystem = {
    pre-commit = {
      settings.hooks = {
        gitlint.enable = true;
        typos = {
          enable = true;
          excludes = [
            "^LICENSES/.*"
            "^tests/resources/.*"
          ];
        };
        end-of-file-fixer = {
          enable = true;
          excludes = [
            "^LICENSES/.*"
            "^tests/resources/.*"
          ];
        };
        trim-trailing-whitespace = {
          enable = true;
          excludes = [
            "^LICENSES/.*"
            "^tests/resources/.*"
          ];
        };
        actionlint.enable = true;
        deadnix.enable = true;
        isort = {
          enable = true;
          settings.profile = "black";
        };
        nixfmt.enable = true;
        ruff.enable = true;
        ruff-format.enable = true;
        reuse.enable = true;
        shellcheck.enable = true;
        statix = {
          enable = true;
          args = [
            "fix"
          ];
        };
      };
    };
  };
}
