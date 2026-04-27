# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{ ... }:
{
  perSystem =
    { config, pkgs, ... }:
    {
      formatter =
        let
          inherit (config.pre-commit.settings) package configFile;
        in
        pkgs.writeShellScriptBin "pre-commit-run" ''
          exec ${pkgs.lib.getExe package} run --all-files --config ${configFile}
        '';
    };
}
