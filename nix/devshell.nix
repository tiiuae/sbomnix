# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  perSystem = {
    pkgs,
    self',
    ...
  }: {
    devShells.default = pkgs.mkShell rec {
      name = "sbomnix-dev-shell";

      packages =
        (with pkgs; [
          coreutils
          curl
          gnugrep
          gnused
          graphviz
          grype
          gzip
          nix
          reuse

          # a python with all python packages imported by sbomnix itself
          (pkgs.python3.withPackages (ps:
            with ps; [
              beautifulsoup4
              colorlog
              graphviz
              numpy
              packageurl-python
              packaging
              pandas
              requests
              requests-cache
              tabulate
              venvShellHook
              wheel
            ]))
        ])
        ++ (with self'.packages; [
          vulnix
          nix-visualize
        ]);
    };
  };
}
