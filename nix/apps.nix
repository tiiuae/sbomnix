# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  perSystem =
    { self', ... }:
    {
      apps =
        let
          inherit (self'.packages) sbomnix;
          mkApp = program: description: {
            type = "app";
            inherit program;
            meta = {
              inherit description;
            };
          };
        in
        {
          # nix run .#nixgraph
          nixgraph = mkApp "${sbomnix}/bin/nixgraph" "Visualize nix package dependencies";

          # nix run .#vulnxscan
          vulnxscan = mkApp "${sbomnix}/bin/vulnxscan" "Scan nix artifacts or SBOMs for vulnerabilities";

          # nix run .#vulnxscan-diff
          vulnxscan-diff = mkApp "${sbomnix}/bin/vulnxscan-diff" "Diff two vulnxscan SARIF documents as markdown";

          # nix run .#provenance
          provenance = mkApp "${sbomnix}/bin/provenance" "Generate SLSA provenance for a nix target";
        };
    };
}
