# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  description = "Flakes file for sbomnix";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      # forEachSystem [ "x86_64-linux" ] { example = true; } -> { x86_64-linux.example = true }
      forEachSystem = nixpkgs.lib.genAttrs systems;
      # Imports a module expecting a system to be passed in
      importExpectingSystem = module: system: import module {
        pkgs = import nixpkgs { inherit system; };
      };
      vulnxscan = importExpectingSystem ./scripts/vulnxscan/vulnxscan.nix;
      repology_cli = importExpectingSystem ./scripts/repology/repology_cli.nix;
      nixupdate = importExpectingSystem ./scripts/nixupdate/nixupdate.nix;
      sbomnix = importExpectingSystem ./default.nix;
      sbomnix-shell = importExpectingSystem ./shell.nix;
    in
    {
      # nix package
      packages = forEachSystem (system: {
        repology_cli = repology_cli system;
        nixupdate = nixupdate system;
        vulnxscan = vulnxscan system;
        sbomnix = sbomnix system;
        default = sbomnix system;
      });

      apps = forEachSystem (system: {
        # nix run .#sbomnix
        sbomnix = {
          type = "app";
          program = "${self.packages.${system}.sbomnix}/bin/sbomnix";
        };

        # nix run .#nixgraph
        nixgraph = {
          type = "app";
          program = "${self.packages.${system}.sbomnix}/bin/nixgraph";
        };

        # nix run .#vulnxscan
        vulnxscan = {
          type = "app";
          program = "${self.packages.${system}.vulnxscan}/bin/vulnxscan.py";
        };

        # nix run .#repology_cli
        repology_cli = {
          type = "app";
          program = "${self.packages.${system}.repology_cli}/bin/repology_cli.py";
        };

        # nix run .#nix_outdated
        nix_outdated = {
          type = "app";
          program = "${self.packages.${system}.nixupdate}/bin/nix_outdated.py";
        };

        # nix run .#nix_secupdates
        nix_secupdates = {
          type = "app";
          program = "${self.packages.${system}.nixupdate}/bin/nix_secupdates.py";
        };
      });

      # nix develop
      devShells = forEachSystem (system: {
        default = sbomnix-shell system;
      });
    };
}
