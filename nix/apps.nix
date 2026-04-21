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
          # nix run .#repology_cli
          repology_cli = mkApp "${sbomnix}/bin/repology_cli" "Query Repology using an SBOM as input";

          # nix run .#repology_cve
          repology_cve = mkApp "${sbomnix}/bin/repology_cve" "Find CVEs for packages known to Repology";

          # nix run .#nix_outdated
          nix_outdated = mkApp "${sbomnix}/bin/nix_outdated" "List outdated nix dependencies in priority order";

          # nix run .#nixgraph
          nixgraph = mkApp "${sbomnix}/bin/nixgraph" "Visualize nix package dependencies";

          # nix run .#nixmeta
          nixmeta = mkApp "${sbomnix}/bin/nixmeta" "Summarize nixpkgs meta-attributes";

          # nix run .#vulnxscan
          vulnxscan = mkApp "${sbomnix}/bin/vulnxscan" "Scan nix artifacts or SBOMs for vulnerabilities";

          # nix run .#provenance
          provenance = mkApp "${sbomnix}/bin/provenance" "Generate SLSA provenance for a nix target";
        };
    };
}
