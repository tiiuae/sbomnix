# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

{ ... }:

let
  mkPackage =
    {
      name,
      pname,
      version,
      description,
      homepage,
    }:
    builtins.derivation {
      inherit name pname version;
      system = builtins.currentSystem;
      builder = "/bin/sh";
      args = [
        "-c"
        "echo ${name} > $out"
      ];
      meta = {
        inherit description homepage;
        license = {
          shortName = "Apache-2.0";
          spdxId = "Apache-2.0";
        };
      };
    };
in
{
  first = mkPackage {
    name = "sbomnix-meta-first-1.0";
    pname = "sbomnix-meta-first";
    version = "1.0";
    description = "First sbomnix metadata fixture package";
    homepage = "https://example.test/sbomnix-meta-first";
  };

  second = mkPackage {
    name = "sbomnix-meta-second-2.0";
    pname = "sbomnix-meta-second";
    version = "2.0";
    description = "Second sbomnix metadata fixture package";
    homepage = "https://example.test/sbomnix-meta-second";
  };
}
