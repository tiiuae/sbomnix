# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

{
  system ? builtins.currentSystem,
}:

let
  mkTestDerivation =
    {
      name,
      pname,
      version,
      command,
    }:
    builtins.derivation {
      inherit
        name
        pname
        system
        version
        ;
      builder = "/bin/sh";
      args = [
        "-c"
        command
      ];
    };

  first = mkTestDerivation {
    name = "sbomnix-test-first-1.0";
    pname = "sbomnix-test-first";
    version = "1.0";
    command = "echo first > $out";
  };

  second = mkTestDerivation {
    name = "sbomnix-test-second-1.0";
    pname = "sbomnix-test-second";
    version = "1.0";
    command = "echo ${first} > $out";
  };
in
mkTestDerivation {
  name = "sbomnix-test-third-1.0";
  pname = "sbomnix-test-third";
  version = "1.0";
  command = "echo ${second} > $out";
}
