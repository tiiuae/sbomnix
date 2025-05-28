# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  lib,
  self,
  ...
}:
{
  perSystem =
    {
      self',
      pkgs,
      ...
    }:
    {
      checks =
        {
          pylint =
            pkgs.runCommandLocal "pylint"
              {
                nativeBuildInputs = [ self'.devShells.default.nativeBuildInputs ];
              }
              ''
                cd ${self.outPath}
                export HOME=/tmp
                pylint \
                  $(find . -name "*.py") \
                  --reports n \
                  --enable=useless-suppression \
                  --fail-on=useless-suppression \
                  --disable=duplicate-code
                touch $out
              '';
        }
        //
        # Force a build of all packages during a `nix flake check`
        (with lib; mapAttrs' (n: nameValuePair "package-${n}") self'.packages);
    };
}
