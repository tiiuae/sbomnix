# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  description = "Flakes file for sbomnix";

  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;

  outputs = { self, nixpkgs }:
    let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
      sbomnix = import ./default.nix { pkgs = pkgs; };
      sbomnix-shell = import ./shell.nix { pkgs = pkgs; };
    in rec {
      
      # nix package
      packages.x86_64-linux = {
        inherit sbomnix;
        default = sbomnix;
      };

      # nix run .#sbomnix
      apps.x86_64-linux.sbomnix = {
        type = "app";
        program = "${self.packages.x86_64-linux.sbomnix}/bin/sbomnix";
      };

      # nix run .#nixgraph
      apps.x86_64-linux.nixgraph = {
        type = "app";
        program = "${self.packages.x86_64-linux.sbomnix}/bin/nixgraph";
      };

      # nix run .#vulnxscan
      apps.x86_64-linux.vulnxscan = {
        type = "app";
        program = "${self.packages.x86_64-linux.sbomnix}/bin/vulnxscan";
      };

      # nix develop
      devShells.x86_64-linux.default = sbomnix-shell;
    };
}
