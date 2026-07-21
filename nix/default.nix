# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{ inputs, ... }:
{
  imports = [
    ./apps.nix
    ./formatter.nix
    ./packages.nix
    ./git-hooks.nix
  ];
  perSystem =
    { system, ... }:
    {
      # df-diskcache upstream pins pandas<3, but its test suite passes with
      # pandas 3: relax the pin for all python envs in this flake.
      # The same fix is in review for nixpkgs in
      # https://github.com/NixOS/nixpkgs/pull/540439; this overlay can be
      # removed once the nixpkgs pin includes that change.
      _module.args.pkgs = import inputs.nixpkgs {
        inherit system;
        overlays = [
          (_final: prev: {
            pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [
              (_pyfinal: pyprev: {
                dfdiskcache = pyprev.dfdiskcache.overridePythonAttrs (old: {
                  pythonRelaxDeps = (old.pythonRelaxDeps or [ ]) ++ [ "pandas" ];
                });
              })
            ];
          })
        ];
      };
    };
}
