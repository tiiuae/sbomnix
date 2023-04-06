# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  description = "Flakes file for sbomnix";

  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;

  outputs = { self, nixpkgs }:
    let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
      vulnxscan = import ./scripts/vulnxscan/vulnxscan.nix { pkgs = pkgs; };
      repology_cli = import ./scripts/repology/repology_cli.nix { pkgs = pkgs; };
      nix_outdated = import ./scripts/nixupdate/nix_outdated.nix { pkgs = pkgs; };
      sbomnix = import ./default.nix { pkgs = pkgs; };
      sbomnix-shell = import ./shell.nix { pkgs = pkgs; };
    in rec {
      
      # nix package
      packages.x86_64-linux = {
        inherit repology_cli;
        inherit nix_outdated;
        inherit vulnxscan;
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
        program = "${self.packages.x86_64-linux.vulnxscan}/bin/vulnxscan.py";
      };

      # nix run .#repology_cli
      apps.x86_64-linux.repology_cli = {
        type = "app";
        program = "${self.packages.x86_64-linux.repology_cli}/bin/repology_cli.py";
      };

      # nix run .#nix_outdated
      apps.x86_64-linux.nix_outdated= {
        type = "app";
        program = "${self.packages.x86_64-linux.nix_outdated}/bin/nix_outdated.py";
      };

      # nix develop
      devShells.x86_64-linux.default = sbomnix-shell;
    };
}
