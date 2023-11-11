# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  perSystem = {self', ...}: {
    apps = let
      inherit (self'.packages) sbomnix;
    in {
      # nix run .#repology_cli
      repology_cli = {
        type = "app";
        program = "${sbomnix}/bin/repology_cli";
      };

      # nix run .#repology_cve
      repology_cve = {
        type = "app";
        program = "${sbomnix}/bin/repology_cve";
      };

      # nix run .#nix_outdated
      nix_outdated = {
        type = "app";
        program = "${sbomnix}/bin/nix_outdated";
      };

      # nix run .#nixgraph
      nixgraph = {
        type = "app";
        program = "${sbomnix}/bin/nixgraph";
      };

      # nix run .#vulnxscan
      vulnxscan = {
        type = "app";
        program = "${sbomnix}/bin/vulnxscan";
      };
    };
  };
}
