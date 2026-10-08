# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# Two packages that build the same output path from different derivations:
# they only differ in how the fixed-output source is fetched. Whichever is
# realised first becomes the recorded deriver of the shared output.
{
  system ? builtins.currentSystem,
}:

let
  src =
    mirror:
    builtins.derivation {
      inherit system;
      name = "sbomnix-test-src";
      builder = "/bin/sh";
      args = [
        "-c"
        "echo hello > $out # fetched from ${mirror}"
      ];
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      outputHash = "sha256-WJG1tSLV3whtD/CxEPvZ0hu0/HFjrzTQgoai6Eb2vgM=";
    };

  app =
    mirror:
    builtins.derivation {
      inherit system;
      name = "sbomnix-test-app-1.0";
      builder = "/bin/sh";
      args = [
        "-c"
        "echo ${src mirror} > $out"
      ];
    };
in
{
  a = app "mirror-a";
  b = app "mirror-b";
}
