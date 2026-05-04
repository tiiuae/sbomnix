# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# Look up nixpkgs metadata for a list of store-path names.
# pkgs must be the exact nixpkgs used to build the target — never import <nixpkgs>
# directly, as channels are unrelated to the target and cause version mismatches.
# Usage: nix eval --json --file meta.nix \
#          --apply 'f: f { names = ["hello-2.12.3" ...]; pkgs = import /path/to/nixpkgs {}; }'

{
  names ? [ ],
  pkgs,
}:

let
  lib = pkgs.lib;

  # tryEval guards sets that may be defined-but-throw in a given nixpkgs revision
  # (e.g. nodePackages was removed and replaced with top-level attributes).
  _safeSet =
    attr:
    let
      res = builtins.tryEval (pkgs.${attr} or { });
    in
    if res.success && builtins.isAttrs res.value then res.value else { };

  # Precompute each sub-package set once; Nix's lazy evaluation memoises them.
  _haskellPkgs = _safeSet "haskellPackages";
  _python3Pkgs = _safeSet "python3Packages";
  _perlPkgs = _safeSet "perlPackages";
  _rubyPkgs = _safeSet "rubyPackages";
  _ocamlPkgs = _safeSet "ocamlPackages";
  _rPkgs = _safeSet "rPackages";
  _nodePkgs = _safeSet "nodePackages";
  _qt6Pkgs = _safeSet "qt6";

  # Ordered by lookup frequency; extend as needed
  _searchSets = [
    pkgs
    _haskellPkgs
    _python3Pkgs
    _perlPkgs
    _rubyPkgs
    _ocamlPkgs
    _rPkgs
    _nodePkgs
    _qt6Pkgs
  ];

  # Re-order search sets to prioritise the sub-package set that matches a
  # known language prefix, reducing false positives from pname collisions.
  # Metadata (license, homepage, description) is stable across minor version
  # differences so the match is by pname only — not exact store-path name.
  _prefixedSearchSets =
    name:
    if builtins.match "python[23][.][0-9]+-.+" name != null then
      [
        _python3Pkgs
        pkgs
      ]
    else if
      (
        builtins.match "perl[0-9]+[.][0-9]+[.][0-9]+-.+" name != null
        || builtins.match "perl[0-9]+[.][0-9]+-.+" name != null
      )
    then
      [
        _perlPkgs
        pkgs
      ]
    else if builtins.match "ruby[0-9]+[.][0-9]+-.+" name != null then
      [
        _rubyPkgs
        pkgs
      ]
    else
      _searchSets;

  # Extract the pname from a full derivation name such as "alsa-utils-1.2.14".
  # Handles common nixpkgs naming conventions:
  #   python3.13-requests-2.31.0   → requests    (python3Packages prefix)
  #   perl5.42.0-CGI-4.59          → CGI         (perlPackages, 3-part version)
  #   perl5.40-XML-Simple-1.0      → XML-Simple  (perlPackages, 2-part version)
  #   ruby3.3-kramdown-2.4.0       → kramdown    (rubyPackages prefix)
  #   alsa-utils-1.2.14            → alsa-utils  (standard)
  #   hello-2.12.3                 → hello
  #   glibc-2.42-51                → glibc       (not glibc-2.42, greedy trap)
  #   3proxy-0.9.6                 → 3proxy      (digit-leading name)
  _pnameFromName =
    name:
    let
      # Same pname pattern as mStd: stops at the first dash-digit boundary so
      # that "python3.13-asn1crypto-1.5.1-unstable-2023-11-03" → "asn1crypto"
      # and "perl5.42.0-XML-Simple-2.25-unstable-2023-05-01" → "XML-Simple".
      # The greedy (.+) alternative fails for unstable-date-suffixed names.
      # Dots are permitted inside a segment to handle pnames like "vid.stab",
      # "tap.py", and "wheezy.template".
      _pnamePat = "[a-zA-Z0-9][a-zA-Z0-9_+.]*(-[a-zA-Z][a-zA-Z0-9_+.]*)*";
      mPy = builtins.match "python[23][.][0-9]+-(${_pnamePat})-[0-9].*" name;
      mPerl3 = builtins.match "perl[0-9]+[.][0-9]+[.][0-9]+-(${_pnamePat})-[0-9].*" name;
      mPerl = builtins.match "perl[0-9]+[.][0-9]+-(${_pnamePat})-[0-9].*" name;
      mRuby = builtins.match "ruby[0-9]+[.][0-9]+-(${_pnamePat})-[0-9].*" name;
      # Stops the pname at the first dash-followed-by-digit so that names like
      # "glibc-2.42-51" yield "glibc" rather than "glibc-2.42".  Dash-segments
      # that begin with a letter (e.g. "alsa-utils", "bash-interactive") are
      # included.  Returns a two-element list; lib.head picks the pname.
      mStd = builtins.match "([a-zA-Z0-9][a-zA-Z0-9_+.]*(-[a-zA-Z][a-zA-Z0-9_+.]*)*)-[0-9].*" name;
      mBare = builtins.match "([a-zA-Z0-9][a-zA-Z0-9_+.-]*)" name;
    in
    if mPy != null then
      lib.head mPy
    else if mPerl3 != null then
      lib.head mPerl3
    else if mPerl != null then
      lib.head mPerl
    else if mRuby != null then
      lib.head mRuby
    else if mStd != null then
      lib.head mStd
    else if mBare != null then
      lib.head mBare
    else
      null;

  # Try to look up pname in a single package set, catching evaluation errors.
  _lookupPname =
    pname: s:
    let
      res = builtins.tryEval (
        let
          c = s.${pname} or null;
          ok = c != null && lib.isDerivation c;
        in
        if ok then c else null
      );
    in
    if res.success then res.value else null;

  # Search pname across an ordered list of sets, returning the first match.
  _lookupInSets = pname: sets: lib.findFirst (x: x != null) null (map (_lookupPname pname) sets);

  # Strip the last dash-word suffix from a pname, e.g.
  # "bash-interactive" → "bash", "ghostscript-with-X" → "ghostscript-with".
  _stripSuffix =
    pname:
    let
      m = builtins.match "(.*)-[a-zA-Z][a-zA-Z0-9_+]*" pname;
    in
    if m != null then lib.head m else null;

  # Patch files appear in build-time closures but are not nixpkgs packages.
  _isPatchLikeName = name: builtins.match ".*[.]patch([.][a-zA-Z0-9]+)?$" name != null;

  # Find a derivation whose pname matches.  Lookup order:
  #   1. Exact pname in the language-prefixed search sets
  #   2. Strip trailing dash-word suffixes (up to two levels). For python/perl/ruby
  #      prefixes, also try the language sub-set before pkgs:
  #      "python3.13-gyp-unstable-2024-02-07" → python3Packages.gyp
  #      "ruby3.3-kramdown-parser-gfm-1.1.0" → rubyPackages.kramdown-parser-gfm
  #      Otherwise, strip only in pkgs:
  #      "bash-interactive" → "bash", "ghostscript-with-X" → "ghostscript"
  #      (restricted for non-language names to prevent language sub-sets from producing
  #      false positives, e.g. "speech-dispatcher" stripped to "speech"
  #      matching rPackages.speech)
  #   3. Named convention fallbacks (Perl, C++, GTK, webkitgtk, dash→underscore)
  #   4. Attr-name divergence fallbacks: lowercase, dash-removed, digit-suffix,
  #      underscore-major-version, dot→dash, plus→"plus" — all performed against
  #      the language-prefixed sets to preserve correct package-set disambiguation
  _findByStoreName =
    name:
    let
      pname = _pnameFromName name;
      sets = _prefixedSearchSets name;
      isPerlName =
        builtins.match "perl[0-9]+[.][0-9]+[.][0-9]+-.+" name != null
        || builtins.match "perl[0-9]+[.][0-9]+-.+" name != null;
      stripSets =
        if
          builtins.match "python[23][.][0-9]+-.+" name != null
          || builtins.match "ruby[0-9]+[.][0-9]+-.+" name != null
        then
          sets
        else
          [ pkgs ];
    in
    if _isPatchLikeName name || pname == null then
      null
    else
      let
        r0 = _lookupInSets pname sets;
        # Perl: "Authen-SASL" → perlPackages.AuthenSASL (dashes removed).
        # Try this before suffix stripping to avoid false positives like
        # "CGI-Fast" → "CGI" and "IO-HTML" → "IO".
        rPerl =
          if isPerlName && r0 == null then
            let
              noDash = lib.replaceStrings [ "-" ] [ "" ] pname;
            in
            if noDash != pname then _lookupPname noDash _perlPkgs else null
          else
            null;
        # Suffix-strip cascade: use the language sub-set only for explicitly
        # language-prefixed names, otherwise restrict to pkgs to avoid false
        # positives from unrelated top-level name fragments.
        p1 = if r0 == null && rPerl == null then _stripSuffix pname else null;
        r1 = if p1 != null then _lookupInSets p1 stripSets else null;
        p2 = if r1 == null && p1 != null then _stripSuffix p1 else null;
        r2 = if p2 != null then _lookupInSets p2 stripSets else null;
        allFailed = r0 == null && r1 == null && r2 == null;
        # C++ libs: "libsigc++" → pkgs.libsigcxx, "libxml++" → pkgs.libxmlxx
        rXx =
          if allFailed && rPerl == null && lib.hasSuffix "++" pname then
            _lookupInSets ((lib.removeSuffix "++" pname) + "xx") [ pkgs ]
          else
            null;
        # GTK: "gtk+" → pkgs.gtk2, "gtk+3" → pkgs.gtk3
        rGtk =
          if allFailed && rPerl == null && rXx == null then
            let
              gtkAttr =
                if pname == "gtk+" then
                  "gtk2"
                else if pname == "gtk+3" then
                  "gtk3"
                else
                  null;
            in
            if gtkAttr != null then _lookupPname gtkAttr pkgs else null
          else
            null;
        # webkitgtk: "webkitgtk-2.52.2+abi=4.1" → pkgs.webkitgtk_4_1
        rWk =
          if allFailed && rPerl == null && rXx == null && rGtk == null then
            let
              m = builtins.match "[^+]*[+]abi=([0-9]+)[.]([0-9]+).*" name;
              attr = if m != null then "webkitgtk_${lib.head m}_${lib.last m}" else null;
            in
            if attr != null then _lookupPname attr pkgs else null
          else
            null;
        # Dash → underscore: "cyrus-sasl" → pkgs.cyrus_sasl, "lm-sensors" → pkgs.lm_sensors
        rUs =
          if allFailed && rPerl == null && rXx == null && rGtk == null && rWk == null then
            let
              uscore = lib.replaceStrings [ "-" ] [ "_" ] pname;
            in
            if uscore != pname then _lookupInSets uscore sets else null
          else
            null;
        # Lowercase: "CUnit" → pkgs.cunit, "ldacBT" → pkgs.ldacbt
        rLower =
          if allFailed && rPerl == null && rXx == null && rGtk == null && rWk == null && rUs == null then
            let
              lc = lib.toLower pname;
            in
            if lc != pname then _lookupInSets lc sets else null
          else
            null;
        # Leading digit attrs are often underscore-prefixed in nixpkgs:
        # "3proxy" → pkgs._3proxy
        rLeadingDigit =
          if
            allFailed
            && rPerl == null
            && rXx == null
            && rGtk == null
            && rWk == null
            && rUs == null
            && rLower == null
          then
            let
              attr = if builtins.match "^[0-9].*" pname != null then "_${pname}" else null;
            in
            if attr != null then _lookupInSets attr sets else null
          else
            null;
        # Dash removed: "boehm-gc" → pkgs.boehmgc, "wireless-tools" → pkgs.wirelesstools
        rNoDash =
          if
            allFailed
            && rPerl == null
            && rXx == null
            && rGtk == null
            && rWk == null
            && rUs == null
            && rLower == null
            && rLeadingDigit == null
          then
            let
              noDash = lib.replaceStrings [ "-" ] [ "" ] pname;
            in
            if noDash != pname then _lookupInSets noDash sets else null
          else
            null;
        # Digit suffix: "grub" → pkgs.grub2, "geoclue" → pkgs.geoclue2,
        # "libusb" → pkgs.libusb1, "liblqr" → pkgs.liblqr1
        rDigit =
          if
            allFailed
            && rPerl == null
            && rXx == null
            && rGtk == null
            && rWk == null
            && rUs == null
            && rLower == null
            && rLeadingDigit == null
            && rNoDash == null
          then
            lib.findFirst (x: x != null) null (
              map (n: _lookupInSets (pname + toString n) sets) [
                1
                2
                3
                4
              ]
            )
          else
            null;
        # Underscore-major-version: "libsoup-3.6.6" → pkgs.libsoup_3,
        # "spidermonkey-140.7.1" → pkgs.spidermonkey_140
        rUnderscoreMajor =
          if
            allFailed
            && rPerl == null
            && rXx == null
            && rGtk == null
            && rWk == null
            && rUs == null
            && rLower == null
            && rLeadingDigit == null
            && rNoDash == null
            && rDigit == null
          then
            let
              m = builtins.match "${pname}-([0-9]+).*" name;
              attr = if m != null then "${pname}_${lib.head m}" else null;
            in
            if attr != null then _lookupInSets attr sets else null
          else
            null;
        # Dot → dash in attr: "vid.stab" → pkgs.vid-stab
        rDotDash =
          if
            allFailed
            && rPerl == null
            && rXx == null
            && rGtk == null
            && rWk == null
            && rUs == null
            && rLower == null
            && rLeadingDigit == null
            && rNoDash == null
            && rDigit == null
            && rUnderscoreMajor == null
          then
            let
              dotDash = lib.replaceStrings [ "." ] [ "-" ] pname;
            in
            if dotDash != pname then _lookupInSets dotDash sets else null
          else
            null;
        # Plus → "plus": "memtest86+" → pkgs.memtest86plus
        rPlus =
          if
            allFailed
            && rPerl == null
            && rXx == null
            && rGtk == null
            && rWk == null
            && rUs == null
            && rLower == null
            && rLeadingDigit == null
            && rNoDash == null
            && rDigit == null
            && rUnderscoreMajor == null
            && rDotDash == null
          then
            let
              plusName = lib.replaceStrings [ "+" ] [ "plus" ] pname;
            in
            if plusName != pname then _lookupInSets plusName sets else null
          else
            null;
      in
      if r0 != null then
        r0
      else if r1 != null then
        r1
      else if r2 != null then
        r2
      else if rPerl != null then
        rPerl
      else if rXx != null then
        rXx
      else if rGtk != null then
        rGtk
      else if rWk != null then
        rWk
      else if rUs != null then
        rUs
      else if rLower != null then
        rLower
      else if rLeadingDigit != null then
        rLeadingDigit
      else if rNoDash != null then
        rNoDash
      else if rDigit != null then
        rDigit
      else if rUnderscoreMajor != null then
        rUnderscoreMajor
      else if rDotDash != null then
        rDotDash
      else
        rPlus;

  # Output format — project only JSON-safe fields from meta
  filteredMeta = meta: {
    description = meta.description or null;
    homepage = meta.homepage or null;
    unfree = meta.unfree or false;
    position = meta.position or null;
    license = meta.license or { };
    maintainers = map (m: { email = m.email or ""; }) (
      lib.filter lib.isAttrs (meta.maintainers or [ ])
    );
  };

  toEntry =
    name:
    let
      drv = _findByStoreName name;
    in
    if drv == null then
      null
    else
      {
        inherit name;
        value = {
          inherit name;
          pname = drv.pname or name;
          version = drv.version or "";
          meta = filteredMeta (drv.meta or { });
        };
      };

in
lib.listToAttrs (lib.filter (x: x != null) (map toEntry names))
