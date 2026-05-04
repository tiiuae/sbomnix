# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# Minimal fake nixpkgs for meta.nix unit tests.
# Provides a self-contained lib (no import <nixpkgs> required) and a small set
# of derivations whose pnames exercise the lookup paths in meta.nix.

{ ... }:

let
  # Self-contained lib subset — only the functions used by meta.nix.
  lib = rec {
    head = builtins.head;
    last = list: builtins.elemAt list (builtins.length list - 1);
    filter = builtins.filter;
    foldl = builtins.foldl';

    foldlAttrs =
      f: init: set:
      builtins.foldl' (acc: k: f acc k set.${k}) init (builtins.attrNames set);

    findFirst =
      pred: fallback: list:
      let
        go =
          i:
          if i >= builtins.length list then
            fallback
          else
            let
              x = builtins.elemAt list i;
            in
            if pred x then x else go (i + 1);
      in
      go 0;

    isAttrs = builtins.isAttrs;
    isDerivation = x: (x.type or null) == "derivation";

    hasSuffix =
      suffix: str:
      let
        sl = builtins.stringLength suffix;
        xl = builtins.stringLength str;
      in
      sl <= xl && builtins.substring (xl - sl) sl str == suffix;

    removeSuffix =
      suffix: str:
      if hasSuffix suffix str then
        builtins.substring 0 (builtins.stringLength str - builtins.stringLength suffix) str
      else
        str;

    replaceStrings = builtins.replaceStrings;

    toLower =
      s:
      let
        table = {
          A = "a";
          B = "b";
          C = "c";
          D = "d";
          E = "e";
          F = "f";
          G = "g";
          H = "h";
          I = "i";
          J = "j";
          K = "k";
          L = "l";
          M = "m";
          N = "n";
          O = "o";
          P = "p";
          Q = "q";
          R = "r";
          S = "s";
          T = "t";
          U = "u";
          V = "v";
          W = "w";
          X = "x";
          Y = "y";
          Z = "z";
        };
        conv =
          i:
          let
            c = builtins.substring i 1 s;
          in
          table.${c} or c;
      in
      builtins.concatStringsSep "" (map conv (builtins.genList (x: x) (builtins.stringLength s)));

    listToAttrs = builtins.listToAttrs;
  };

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
  inherit lib;

  # Empty sub-package sets (meta.nix probes these via _safeSet).
  haskellPackages = { };
  python3Packages = { };
  perlPackages = { };
  rubyPackages = { };
  ocamlPackages = { };
  rPackages = { };
  nodePackages = { };
  qt6 = { };

  # attr == pname: exact lookup path
  "sbomnix-meta-first" = mkPackage {
    name = "sbomnix-meta-first-1.0";
    pname = "sbomnix-meta-first";
    version = "1.0";
    description = "First sbomnix metadata fixture package";
    homepage = "https://example.test/sbomnix-meta-first";
  };

  "sbomnix-meta-second" = mkPackage {
    name = "sbomnix-meta-second-2.0";
    pname = "sbomnix-meta-second";
    version = "2.0";
    description = "Second sbomnix metadata fixture package";
    homepage = "https://example.test/sbomnix-meta-second";
  };

  # Packages used to test attr-name divergence fallbacks:

  # lowercase fallback: pname "TestCaseDiverge", attr "testcasediverge"
  testcasediverge = mkPackage {
    name = "testcasediverge-1.0";
    pname = "TestCaseDiverge";
    version = "1.0";
    description = "Fixture: case divergence between pname and attr";
    homepage = "https://example.test/testcasediverge";
  };

  # dash-removed fallback: pname "test-dashremoved", attr "testdashremoved"
  testdashremoved = mkPackage {
    name = "testdashremoved-1.0";
    pname = "test-dashremoved";
    version = "1.0";
    description = "Fixture: dash removed in attr name";
    homepage = "https://example.test/test-dashremoved";
  };

  # digit-suffix fallback: pname "test-digitsuffix", attr "test-digitsuffix2"
  "test-digitsuffix2" = mkPackage {
    name = "test-digitsuffix2-1.0";
    pname = "test-digitsuffix";
    version = "1.0";
    description = "Fixture: digit suffix in attr name";
    homepage = "https://example.test/test-digitsuffix";
  };

  # dot→dash fallback: pname "test.dot", attr "test-dot"
  "test-dot" = mkPackage {
    name = "test-dot-1.0";
    pname = "test.dot";
    version = "1.0";
    description = "Fixture: dot in pname";
    homepage = "https://example.test/test-dot";
  };

  # plus→"plus" fallback: pname "test86+", attr "test86plus"
  "test86plus" = mkPackage {
    name = "test86plus-1.0";
    pname = "test86+";
    version = "1.0";
    description = "Fixture: plus sign in pname";
    homepage = "https://example.test/test86plus";
  };
}
