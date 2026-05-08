# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# Minimal fake nixpkgs for meta.nix unit tests.
# Provides a self-contained lib (no import <nixpkgs> required) and a small set
# of derivations whose pnames exercise the lookup paths in meta.nix.

{ ... }:

let
  # Self-contained lib subset, only the functions used by meta.nix.
  lib = rec {
    head = builtins.head;
    last = list: builtins.elemAt list (builtins.length list - 1);
    filter = builtins.filter;
    unique = list: builtins.foldl' (acc: x: if builtins.elem x acc then acc else acc ++ [ x ]) [ ] list;
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
      licenseShort ? "Apache-2.0",
      licenseSpdxId ? "Apache-2.0",
      licenseFullName ? null,
      licenseMeta ? null,
      outputs ? null,
    }:
    builtins.derivation (
      {
        inherit name pname version;
        system = builtins.currentSystem;
        builder = "/bin/sh";
        args = [
          "-c"
          "echo ${name} > $out"
        ];
        meta = {
          inherit description homepage;
          license =
            if licenseMeta != null then
              licenseMeta
            else
              {
                shortName = licenseShort;
                spdxId = licenseSpdxId;
                fullName = licenseFullName;
              };
        };
      }
      // (if outputs == null then { } else { inherit outputs; })
    );
in
{
  inherit lib;

  # Mostly empty sub-package sets; a few contain targeted fixtures used by
  # meta.nix unit tests.
  haskellPackages = {
    camelCrossSet = mkPackage {
      name = "camel-cross-set-1.0";
      pname = "camel-cross-set";
      version = "1.0";
      description = "Fixture: cross-set false positive for dash-to-camelCase";
      homepage = "https://example.test/haskell-camel-cross-set";
      licenseShort = "Haskell-Camel-Cross-Set";
      licenseSpdxId = "LicenseRef-Haskell-Camel-Cross-Set";
    };
    cornelis = mkPackage {
      name = "cornelis-0.2.0.1";
      pname = "cornelis";
      version = "0.2.0.1";
      description = "Fixture: haskell cornelis";
      homepage = "https://example.test/haskell-cornelis";
      licenseShort = "Haskell-Cornelis";
      licenseSpdxId = "LicenseRef-Haskell-Cornelis";
    };
    hello = mkPackage {
      name = "hello-1.0.0.2";
      pname = "hello";
      version = "1.0.0.2";
      description = "Fixture: haskell hello";
      homepage = "https://example.test/haskell-hello";
      licenseShort = "Haskell-Hello";
      licenseSpdxId = "LicenseRef-Haskell-Hello";
    };
    "license-detail" = mkPackage {
      name = "license-detail-1.0";
      pname = "license-detail";
      version = "1.0";
      description = "Fixture: same name with differing full license metadata";
      homepage = "https://example.test/license-detail";
      licenseShort = "License-Detail";
      licenseSpdxId = "LicenseRef-License-Detail";
      licenseFullName = "Fixture License Detail Haskell";
    };
    "same-meta" = mkPackage {
      name = "same-meta-1.0";
      pname = "same-meta";
      version = "1.0";
      description = "Fixture: same metadata collision";
      homepage = "https://example.test/same-meta";
      licenseShort = "Same-Meta";
      licenseSpdxId = "LicenseRef-Same-Meta";
    };
    "split-demo" = mkPackage {
      name = "split-demo-9.9";
      pname = "split-demo";
      version = "9.9";
      description = "Fixture: haskell split-demo";
      homepage = "https://example.test/haskell-split-demo";
      licenseShort = "Haskell-Split-Demo";
      licenseSpdxId = "LicenseRef-Haskell-Split-Demo";
    };
  };
  python3Packages = {
    gyp = mkPackage {
      name = "gyp-0.1";
      pname = "gyp";
      version = "0.1";
      description = "Fixture: python package reached via unstable suffix strip";
      homepage = "https://example.test/gyp";
    };
  };
  perlPackages = {
    CGI = mkPackage {
      name = "perl-CGI-1.0";
      pname = "CGI";
      version = "1.0";
      description = "Fixture: wrong Perl suffix-strip target";
      homepage = "https://example.test/perl-cgi";
      licenseShort = "Wrong-CGI";
      licenseSpdxId = "LicenseRef-Wrong-CGI";
    };
    CGIFast = mkPackage {
      name = "perl-CGI-Fast-2.16";
      pname = "CGI-Fast";
      version = "2.16";
      description = "Fixture: correct Perl dash-removed lookup";
      homepage = "https://example.test/perl-cgi-fast";
      licenseShort = "Correct-CGI-Fast";
      licenseSpdxId = "LicenseRef-Correct-CGI-Fast";
    };
    Encode = mkPackage {
      name = "perl-Encode-1.0";
      pname = "Encode";
      version = "1.0";
      description = "Fixture: wrong Perl suffix-strip target for Encode-Locale";
      homepage = "https://example.test/perl-encode";
      licenseShort = "Wrong-Encode";
      licenseSpdxId = "LicenseRef-Wrong-Encode";
    };
    EncodeLocale = mkPackage {
      name = "perl-Encode-Locale-1.05";
      pname = "Encode-Locale";
      version = "1.05";
      description = "Fixture: correct Perl dash-removed lookup for Encode-Locale";
      homepage = "https://example.test/perl-encode-locale";
      licenseShort = "Correct-Encode-Locale";
      licenseSpdxId = "LicenseRef-Correct-Encode-Locale";
    };
    FCGI = mkPackage {
      name = "perl-FCGI-1.0";
      pname = "FCGI";
      version = "1.0";
      description = "Fixture: wrong Perl suffix-strip target";
      homepage = "https://example.test/perl-fcgi";
      licenseShort = "Wrong-FCGI";
      licenseSpdxId = "LicenseRef-Wrong-FCGI";
    };
    FCGIProcManager = mkPackage {
      name = "perl-FCGI-ProcManager-0.28";
      pname = "FCGI-ProcManager";
      version = "0.28";
      description = "Fixture: correct Perl dash-removed lookup";
      homepage = "https://example.test/perl-fcgi-procmanager";
      licenseShort = "Correct-FCGI-ProcManager";
      licenseSpdxId = "LicenseRef-Correct-FCGI-ProcManager";
    };
    IO = mkPackage {
      name = "perl-IO-1.0";
      pname = "IO";
      version = "1.0";
      description = "Fixture: wrong Perl suffix-strip target for IO-HTML";
      homepage = "https://example.test/perl-io";
      licenseShort = "Wrong-IO";
      licenseSpdxId = "LicenseRef-Wrong-IO";
    };
    IOHTML = mkPackage {
      name = "perl-IO-HTML-1.004";
      pname = "IO-HTML";
      version = "1.004";
      description = "Fixture: correct Perl dash-removed lookup for IO-HTML";
      homepage = "https://example.test/perl-io-html";
      licenseShort = "Correct-IO-HTML";
      licenseSpdxId = "LicenseRef-Correct-IO-HTML";
    };
  };
  rubyPackages = {
    kramdown = mkPackage {
      name = "kramdown-2.4.0";
      pname = "kramdown";
      version = "2.4.0";
      description = "Fixture: ruby package reached via ruby prefix extraction";
      homepage = "https://example.test/kramdown";
    };
  };
  ocamlPackages = { };
  rPackages = {
    speech_dispatcher = mkPackage {
      name = "speech-dispatcher-1.0";
      pname = "speech-dispatcher";
      version = "1.0";
      description = "Fixture: cross-set false positive for dash-to-underscore";
      homepage = "https://example.test/r-speech-dispatcher";
      licenseShort = "R-Speech-Dispatcher";
      licenseSpdxId = "LicenseRef-R-Speech-Dispatcher";
    };
  };
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

  libcap = mkPackage {
    name = "libcap-2.76";
    pname = "libcap";
    version = "2.76";
    description = "Fixture: wrong suffix-strip target for libcap-ng";
    homepage = "https://example.test/libcap";
    licenseShort = "Wrong-Libcap";
    licenseSpdxId = "LicenseRef-Wrong-Libcap";
  };

  libcap_ng = mkPackage {
    name = "libcap-ng-0.9";
    pname = "libcap-ng";
    version = "0.9";
    description = "Fixture: correct dash-to-underscore lookup for libcap-ng";
    homepage = "https://example.test/libcap-ng";
    licenseShort = "Correct-Libcap-Ng";
    licenseSpdxId = "LicenseRef-Correct-Libcap-Ng";
  };

  linux = mkPackage {
    name = "linux-6.18.7";
    pname = "linux";
    version = "6.18.7";
    description = "Fixture: wrong suffix-strip target for linux-headers";
    homepage = "https://example.test/linux";
    licenseShort = "Wrong-Linux";
    licenseSpdxId = "LicenseRef-Wrong-Linux";
  };

  linuxHeaders = mkPackage {
    name = "linux-headers-6.18.7";
    pname = "linux-headers";
    version = "6.18.7";
    description = "Fixture: correct dash-to-camelCase lookup for linux-headers";
    homepage = "https://example.test/linux-headers";
    licenseShort = "Correct-Linux-Headers";
    licenseSpdxId = "LicenseRef-Correct-Linux-Headers";
  };

  cacert = mkPackage {
    name = "nss-cacert-3.121";
    pname = "nss-cacert";
    version = "3.121";
    description = "Fixture: explicit rename lookup for nss-cacert";
    homepage = "https://example.test/nss-cacert";
    licenseShort = "Correct-Nss-Cacert";
    licenseSpdxId = "LicenseRef-Correct-Nss-Cacert";
  };

  # digit-suffix fallback: pname "test-digitsuffix", attr "test-digitsuffix2"
  "test-digitsuffix2" = mkPackage {
    name = "test-digitsuffix2-1.0";
    pname = "test-digitsuffix";
    version = "1.0";
    description = "Fixture: digit suffix in attr name";
    homepage = "https://example.test/test-digitsuffix";
  };

  # underscore-version fallback: pname "openssl", attrs "openssl" and "openssl_1_1"
  openssl = mkPackage {
    name = "openssl-3.0.0";
    pname = "openssl";
    version = "3.0.0";
    description = "Fixture: wrong direct attr for older OpenSSL store names";
    homepage = "https://example.test/openssl-3";
    licenseShort = "Wrong-OpenSSL-3";
    licenseSpdxId = "LicenseRef-Wrong-OpenSSL-3";
  };

  openssl_1_1 = mkPackage {
    name = "openssl-1.1.1w";
    pname = "openssl";
    version = "1.1.1w";
    description = "Fixture: correct underscore major-minor OpenSSL attr";
    homepage = "https://example.test/openssl-1-1";
    licenseShort = "Correct-OpenSSL-1-1";
    licenseSpdxId = "LicenseRef-Correct-OpenSSL-1-1";
  };

  # underscore-version fallback: pname "libsoup", attr "libsoup_3"
  libsoup_3 = mkPackage {
    name = "libsoup-3.6.6";
    pname = "libsoup";
    version = "3.6.6";
    description = "Fixture: underscore major version in attr name";
    homepage = "https://example.test/libsoup";
  };

  # Dot-to-dash fallback: pname "test.dot", attr "test-dot"
  "test-dot" = mkPackage {
    name = "test-dot-1.0";
    pname = "test.dot";
    version = "1.0";
    description = "Fixture: dot in pname";
    homepage = "https://example.test/test-dot";
  };

  # Plus-to-"plus" fallback: pname "test86+", attr "test86plus"
  "test86plus" = mkPackage {
    name = "test86plus-1.0";
    pname = "test86+";
    version = "1.0";
    description = "Fixture: plus sign in pname";
    homepage = "https://example.test/test86plus";
  };

  # leading-digit pname fallback: pname "3proxy", attr "_3proxy"
  "_3proxy" = mkPackage {
    name = "3proxy-0.9.6";
    pname = "3proxy";
    version = "0.9.6";
    description = "Fixture: leading-digit pname stored under underscore attr";
    homepage = "https://example.test/3proxy";
    licenseShort = "BSD-2-Clause";
    licenseSpdxId = "BSD-2-Clause";
  };

  cve = mkPackage {
    name = "cve-1.0";
    pname = "cve";
    version = "1.0";
    description = "Fixture: would be a false positive for CVE patch files";
    homepage = "https://example.test/cve";
  };

  hello = mkPackage {
    name = "hello-2.12.3";
    pname = "hello";
    version = "2.12.3";
    description = "Fixture: top-level hello";
    homepage = "https://example.test/top-level-hello";
    licenseShort = "Top-Level-Hello";
    licenseSpdxId = "LicenseRef-Top-Level-Hello";
  };

  "license-detail" = mkPackage {
    name = "license-detail-1.0";
    pname = "license-detail";
    version = "1.0";
    description = "Fixture: same name with differing full license metadata";
    homepage = "https://example.test/license-detail";
    licenseShort = "License-Detail";
    licenseSpdxId = "LicenseRef-License-Detail";
    licenseFullName = "Fixture License Detail Top Level";
  };

  cornelis = mkPackage {
    name = "cornelis-0.2.0.1";
    pname = "cornelis";
    version = "0.2.0.1";
    description = "Fixture: top-level cornelis";
    homepage = "https://example.test/top-level-cornelis";
    licenseShort = "Top-Level-Cornelis";
    licenseSpdxId = "LicenseRef-Top-Level-Cornelis";
  };

  "same-meta" = mkPackage {
    name = "same-meta-1.0";
    pname = "same-meta";
    version = "1.0";
    description = "Fixture: same metadata collision";
    homepage = "https://example.test/same-meta";
    licenseShort = "Same-Meta";
    licenseSpdxId = "LicenseRef-Same-Meta";
  };

  "split-demo" = mkPackage {
    name = "split-demo-1.0";
    pname = "split-demo";
    version = "1.0";
    description = "Fixture: top-level split-demo";
    homepage = "https://example.test/top-level-split-demo";
    licenseShort = "Top-Level-Split-Demo";
    licenseSpdxId = "LicenseRef-Top-Level-Split-Demo";
    outputs = [
      "out"
      "doc"
    ];
  };
}
