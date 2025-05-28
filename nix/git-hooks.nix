# SPDX-FileCopyrightText: 2025 TII (SSRC) and the Ghaf contributors
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
      };
    };
  };
}
