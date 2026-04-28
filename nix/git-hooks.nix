# SPDX-FileCopyrightText: 2025-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
{ inputs, ... }:
{
  imports = with inputs; [
    git-hooks-nix.flakeModule
  ];
  perSystem =
    { pkgs, ... }:
    let
      pyrightPythonEnv = pkgs.python3.withPackages (
        pp: with pp; [
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
        ]
      );
      pyrightWrapper = pkgs.writeShellScriptBin "pyright-sbomnix" ''
        exec ${pkgs.lib.getExe pkgs.pyright} --pythonpath ${pyrightPythonEnv}/bin/python "$@"
      '';
    in
    {
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
          nixfmt.enable = true;
          pyright = {
            enable = true;
            pass_filenames = false;
            settings.binPath = "${pyrightWrapper}/bin/pyright-sbomnix";
          };
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
