# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# Look up nixpkgs metadata for a list of store-path names.
# pkgs must be the exact nixpkgs used to build the target.
# Usage: nix eval --json --file meta.nix \
#          --apply 'f: f { names = ["hello-2.12.3" ...]; pkgs = import /path/to/nixpkgs {}; }'

{
  names ? [ ],
  pkgs,
}:

let
  lib = pkgs.lib;

  # tryEval guards sets that may be absent or defined-but-throw in a given
  # nixpkgs revision (e.g. nodePackages was removed and replaced with top-level
  # attributes).
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
  # differences so the match is by pname only, not exact store-path name.
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
  #   python3.13-requests-2.31.0   maps to requests    (python3Packages prefix)
  #   perl5.42.0-CGI-4.59          maps to CGI         (perlPackages, 3-part version)
  #   perl5.40-XML-Simple-1.0      maps to XML-Simple  (perlPackages, 2-part version)
  #   ruby3.3-kramdown-2.4.0       maps to kramdown    (rubyPackages prefix)
  #   alsa-utils-1.2.14            maps to alsa-utils  (standard)
  #   hello-2.12.3                 maps to hello
  #   glibc-2.42-51                maps to glibc       (not glibc-2.42, greedy trap)
  #   3proxy-0.9.6                 maps to 3proxy      (digit-leading name)
  _pnameFromName =
    name:
    let
      # Same pname pattern as mStd: stops at the first dash-digit boundary so
      # that "python3.13-asn1crypto-1.5.1-unstable-2023-11-03" maps to
      # "asn1crypto" and "perl5.42.0-XML-Simple-2.25-unstable-2023-05-01"
      # maps to "XML-Simple".
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

  _lookupPnameList =
    pname: s:
    let
      drv = _lookupPname pname s;
    in
    if drv == null then [ ] else [ drv ];

  # Search pname across an ordered list of sets, preserving every successful
  # match in the winning heuristic tier. The builder uses that ambiguity signal
  # to blank rows where name-only lookup would otherwise guess metadata.
  _lookupAllInSets = pname: sets: builtins.concatLists (map (_lookupPnameList pname) sets);

  _hasMatches = drvs: builtins.length drvs > 0;

  _hasPrefix =
    prefix: str:
    let
      pl = builtins.stringLength prefix;
      sl = builtins.stringLength str;
    in
    pl <= sl && builtins.substring 0 pl str == prefix;

  _isSimpleOutputName = output: builtins.match "[a-zA-Z0-9][a-zA-Z0-9_+-]*" output != null;

  # If name-only lookup found multiple derivations with the same pname, first
  # prefer the candidate whose canonical drv.name exactly matches the store
  # name. If there is no exact match, accept split outputs only when the suffix
  # is a simple declared output name such as "dev" or "doc". This avoids
  # treating unrelated same-pname packages as equally plausible.
  _candidateMatchesSplitOutputName =
    inputName: drv:
    let
      drvName = drv.name or null;
      prefix = if drvName == null then null else "${drvName}-";
      suffix =
        if prefix != null && _hasPrefix prefix inputName then
          builtins.substring (builtins.stringLength prefix) (
            builtins.stringLength inputName - builtins.stringLength prefix
          ) inputName
        else
          null;
      outputs = builtins.filter (output: output != "out") (drv.outputs or [ "out" ]);
    in
    suffix != null && suffix != "" && _isSimpleOutputName suffix && builtins.elem suffix outputs;

  # Return only candidates that prove identity by exact drv.name or declared
  # split-output suffix. Empty means "keep searching"; the final loose fallback
  # handles older pname-only matches after all identity-preserving tiers fail.
  _canonicalCandidatesByIdentity =
    inputName: candidates:
    let
      exactNameMatches = builtins.filter (drv: (drv.name or null) == inputName) candidates;
      splitOutputMatches = builtins.filter (
        drv: _candidateMatchesSplitOutputName inputName drv
      ) candidates;
    in
    if _hasMatches exactNameMatches then
      exactNameMatches
    else if _hasMatches splitOutputMatches then
      splitOutputMatches
    else
      [ ];

  _narrowCandidatesByCanonicalIdentity =
    inputName: candidates:
    let
      canonicalCandidates = _canonicalCandidatesByIdentity inputName candidates;
    in
    if _hasMatches canonicalCandidates then canonicalCandidates else candidates;

  # Low-loss attr-name rewrites should only be accepted when the candidate is
  # still canonically tied to the package identity for the current lookup pass
  # rather than merely sharing a rewritten attr name.
  _candidateMatchesExpectedPnameOrName =
    inputName: expectedPname: drv:
    (drv.name or null) == inputName || (drv.pname or null) == expectedPname;

  _lookupRewrittenCandidates =
    inputName: expectedPname: rewrittenPname: sets:
    if rewrittenPname == null || rewrittenPname == expectedPname then
      [ ]
    else
      builtins.filter (_candidateMatchesExpectedPnameOrName inputName expectedPname) (
        _lookupAllInSets rewrittenPname sets
      );

  _lookupLowLossRewriteCandidates =
    inputName: currentPname: sets:
    let
      cRewriteExplicit =
        _lookupRewrittenCandidates inputName currentPname (_explicitAttrRewrite currentPname)
          sets;
      cRewriteUnderscore =
        if !_hasMatches cRewriteExplicit then
          _lookupRewrittenCandidates inputName currentPname (lib.replaceStrings [ "-" ] [ "_" ]
            currentPname
          ) sets
        else
          [ ];
      cRewriteCamel =
        if !_hasMatches cRewriteExplicit && !_hasMatches cRewriteUnderscore then
          _lookupRewrittenCandidates inputName currentPname (_dashToCamelCase currentPname) sets
        else
          [ ];
    in
    _firstMatchingCandidates [
      cRewriteExplicit
      cRewriteUnderscore
      cRewriteCamel
    ];

  # Try heuristic tiers in order and stop at the first tier that yields at
  # least one candidate. Later tiers are only fallbacks for total misses.
  _firstMatchingCandidates = candidateLists: lib.findFirst _hasMatches [ ] candidateLists;

  _uppercaseAsciiFirst =
    str:
    let
      first = builtins.substring 0 1 str;
      rest = builtins.substring 1 (builtins.stringLength str - 1) str;
      upperTable = {
        a = "A";
        b = "B";
        c = "C";
        d = "D";
        e = "E";
        f = "F";
        g = "G";
        h = "H";
        i = "I";
        j = "J";
        k = "K";
        l = "L";
        m = "M";
        n = "N";
        o = "O";
        p = "P";
        q = "Q";
        r = "R";
        s = "S";
        t = "T";
        u = "U";
        v = "V";
        w = "W";
        x = "X";
        y = "Y";
        z = "Z";
      };
    in
    if str == "" then "" else "${upperTable.${first} or first}${rest}";

  _dashToCamelCase =
    pname:
    let
      m = builtins.match "([^-]+)-(.*)" pname;
      restToCamel =
        rest:
        let
          next = builtins.match "([^-]+)-(.*)" rest;
        in
        if rest == "" then
          ""
        else if next == null then
          _uppercaseAsciiFirst rest
        else
          "${_uppercaseAsciiFirst (lib.head next)}${restToCamel (lib.last next)}";
    in
    if m == null then null else "${lib.head m}${restToCamel (lib.last m)}";

  _explicitAttrRewrite = pname: if pname == "nss-cacert" then "cacert" else null;

  _normalizeLicenseEntry =
    license:
    if license == null then
      null
    else if lib.isAttrs license then
      if builtins.attrNames license == [ ] then
        null
      else
        {
          spdxId = license.spdxId or null;
          shortName = license.shortName or null;
          fullName = license.fullName or null;
          raw = if (license.raw or null) == null then null else builtins.toString license.raw;
        }
    else
      {
        spdxId = null;
        shortName = null;
        fullName = null;
        raw = builtins.toString license;
      };

  _normalizeLicenseEntries =
    license:
    lib.filter (entry: entry != null) (
      map _normalizeLicenseEntry (
        if license == null then
          [ ]
        else if builtins.isList license then
          license
        else
          [ license ]
      )
    );

  # Strip the last dash-word suffix from a pname, e.g.
  # "bash-interactive" maps to "bash", and "ghostscript-with-X" maps to
  # "ghostscript-with".
  _stripSuffix =
    pname:
    let
      m = builtins.match "(.*)-[a-zA-Z][a-zA-Z0-9_+]*" pname;
    in
    if m != null then lib.head m else null;

  # Patch/diff files appear in build-time closures but are not nixpkgs packages.
  _isPatchLikeName = name: builtins.match ".*[.](patch|diff)([.][a-zA-Z0-9]+)?([?].*)?$" name != null;

  # Source archives and language package uploads may be present in build-time
  # closures, but they are file artifacts rather than exact nixpkgs packages
  # (e.g. Python-3.14.2.tar.xz, foo.whl, bar.cabal).
  _isSourceArtifactName =
    name:
    builtins.match ".*([.]tar([.][a-zA-Z0-9]+)?|[.](tgz|tbz2?|txz|zip|whl|gem|cabal))([?].*)?$" name
    != null;

  # Find derivations whose pname matches. Lookup order:
  #   1. Exact pname in the language-prefixed search sets
  #   2. Low-loss pre-strip rewrites. For explicit python/perl/ruby prefixes,
  #      these may search the language sub-set before pkgs. Unprefixed names
  #      are restricted to pkgs only to avoid cross-set false positives.
  #   3. Strip trailing dash-word suffixes (up to two levels). For python/ruby
  #      prefixes, also try the language sub-set before pkgs:
  #      "python3.13-gyp-unstable-2024-02-07" maps to python3Packages.gyp
  #      "ruby3.3-kramdown-parser-gfm-1.1.0" maps to rubyPackages.kramdown-parser-gfm
  #      Otherwise, strip only in pkgs:
  #      "bash-interactive" maps to "bash", and "ghostscript-with-X" maps to
  #      "ghostscript"
  #      (restricted for non-language names to prevent language sub-sets from producing
  #      false positives, e.g. "speech-dispatcher" stripped to "speech"
  #      matching rPackages.speech)
  #   4. Named convention fallbacks (C++, GTK, webkitgtk)
  #   5. Attr-name divergence fallbacks: lowercase, dash-removed, digit-suffix,
  #      underscore-version, dot to dash, plus to "plus". All of these
  #      run against the language-prefixed sets to preserve package-set
  #      disambiguation.
  _findByStoreName =
    name:
    let
      pname = _pnameFromName name;
      sets = _prefixedSearchSets name;
      isPythonName = builtins.match "python[23][.][0-9]+-.+" name != null;
      isPerlName =
        builtins.match "perl[0-9]+[.][0-9]+[.][0-9]+-.+" name != null
        || builtins.match "perl[0-9]+[.][0-9]+-.+" name != null;
      isRubyName = builtins.match "ruby[0-9]+[.][0-9]+-.+" name != null;
      rewriteSets = if isPythonName || isPerlName || isRubyName then sets else [ pkgs ];
      stripSets = if isPythonName || isRubyName then sets else [ pkgs ];
    in
    if _isPatchLikeName name || _isSourceArtifactName name || pname == null then
      null
    else
      let
        c0 = _lookupAllInSets pname sets;
        c0Identity = _canonicalCandidatesByIdentity name c0;
        # Perl: "Authen-SASL" maps to perlPackages.AuthenSASL after dash
        # removal.
        # Try this before suffix stripping to avoid false positives like
        # "CGI-Fast" mapping to "CGI" and "IO-HTML" mapping to "IO".
        cPerl =
          if isPerlName && !_hasMatches c0Identity then
            let
              noDash = lib.replaceStrings [ "-" ] [ "" ] pname;
            in
            if noDash != pname then _lookupAllInSets noDash [ _perlPkgs ] else [ ]
          else
            [ ];
        cPerlIdentity = _canonicalCandidatesByIdentity name cPerl;
        # Run low-loss attr-name rewrites before suffix stripping so packages
        # such as "libcap-ng" and "linux-headers" resolve to the right nixpkgs
        # attr without broadening unprefixed names beyond pkgs.
        cRewrite =
          if !_hasMatches c0Identity && !_hasMatches cPerlIdentity then
            _lookupLowLossRewriteCandidates name pname rewriteSets
          else
            [ ];
        cRewriteIdentity = _canonicalCandidatesByIdentity name cRewrite;
        # Suffix-strip cascade: only explicit python/ruby names keep their
        # language sub-set here. Non-language names strip against pkgs only to
        # avoid false positives from unrelated top-level fragments; Perl uses
        # its own dash-removal fallback above instead of this cascade. After
        # each strip, retry the same low-loss rewrites before stripping again.
        preStripFailed =
          !_hasMatches c0Identity && !_hasMatches cPerlIdentity && !_hasMatches cRewriteIdentity;
        p1 = if preStripFailed then _stripSuffix pname else null;
        c1 = if p1 != null then _lookupAllInSets p1 stripSets else [ ];
        c1Identity = _canonicalCandidatesByIdentity name c1;
        c1Rewrite =
          if p1 != null && !_hasMatches c1Identity then
            _lookupLowLossRewriteCandidates name p1 stripSets
          else
            [ ];
        c1RewriteIdentity = _canonicalCandidatesByIdentity name c1Rewrite;
        p2 =
          if !_hasMatches c1Identity && !_hasMatches c1RewriteIdentity && p1 != null then
            _stripSuffix p1
          else
            null;
        c2 = if p2 != null then _lookupAllInSets p2 stripSets else [ ];
        c2Identity = _canonicalCandidatesByIdentity name c2;
        c2Rewrite =
          if p2 != null && !_hasMatches c2Identity then
            _lookupLowLossRewriteCandidates name p2 stripSets
          else
            [ ];
        c2RewriteIdentity = _canonicalCandidatesByIdentity name c2Rewrite;
        allFailed =
          preStripFailed
          && !_hasMatches c1Identity
          && !_hasMatches c1RewriteIdentity
          && !_hasMatches c2Identity
          && !_hasMatches c2RewriteIdentity;
        # C++ libs: "libsigc++" maps to pkgs.libsigcxx, and "libxml++" maps
        # to pkgs.libxmlxx.
        cXx =
          if allFailed && lib.hasSuffix "++" pname then
            _lookupAllInSets ((lib.removeSuffix "++" pname) + "xx") [ pkgs ]
          else
            [ ];
        cXxIdentity = _canonicalCandidatesByIdentity name cXx;
        # GTK: "gtk+" maps to pkgs.gtk2, and "gtk+3" maps to pkgs.gtk3.
        cGtk =
          if allFailed && !_hasMatches cXxIdentity then
            let
              gtkAttr =
                if pname == "gtk+" then
                  "gtk2"
                else if pname == "gtk+3" then
                  "gtk3"
                else
                  null;
            in
            if gtkAttr != null then _lookupAllInSets gtkAttr [ pkgs ] else [ ]
          else
            [ ];
        cGtkIdentity = _canonicalCandidatesByIdentity name cGtk;
        # webkitgtk: "webkitgtk-2.52.2+abi=4.1" maps to pkgs.webkitgtk_4_1.
        cWk =
          if allFailed && !_hasMatches cXxIdentity && !_hasMatches cGtkIdentity then
            let
              m = builtins.match "[^+]*[+]abi=([0-9]+)[.]([0-9]+).*" name;
              attr = if m != null then "webkitgtk_${lib.head m}_${lib.last m}" else null;
            in
            if attr != null then _lookupAllInSets attr [ pkgs ] else [ ]
          else
            [ ];
        cWkIdentity = _canonicalCandidatesByIdentity name cWk;
        # Lowercase: "CUnit" maps to pkgs.cunit, and "ldacBT" maps to
        # pkgs.ldacbt.
        cLower =
          if
            allFailed && !_hasMatches cXxIdentity && !_hasMatches cGtkIdentity && !_hasMatches cWkIdentity
          then
            let
              lc = lib.toLower pname;
            in
            if lc != pname then _lookupAllInSets lc sets else [ ]
          else
            [ ];
        cLowerIdentity = _canonicalCandidatesByIdentity name cLower;
        # Leading digit attrs are often underscore-prefixed in nixpkgs:
        # "3proxy" maps to pkgs._3proxy.
        cLeadingDigit =
          if
            allFailed
            && !_hasMatches cXxIdentity
            && !_hasMatches cGtkIdentity
            && !_hasMatches cWkIdentity
            && !_hasMatches cLowerIdentity
          then
            let
              attr = if builtins.match "^[0-9].*" pname != null then "_${pname}" else null;
            in
            if attr != null then _lookupAllInSets attr sets else [ ]
          else
            [ ];
        cLeadingDigitIdentity = _canonicalCandidatesByIdentity name cLeadingDigit;
        # Dash removed: "boehm-gc" maps to pkgs.boehmgc, and
        # "wireless-tools" maps to pkgs.wirelesstools.
        cNoDash =
          if
            allFailed
            && !_hasMatches cXxIdentity
            && !_hasMatches cGtkIdentity
            && !_hasMatches cWkIdentity
            && !_hasMatches cLowerIdentity
            && !_hasMatches cLeadingDigitIdentity
          then
            let
              noDash = lib.replaceStrings [ "-" ] [ "" ] pname;
            in
            if noDash != pname then _lookupAllInSets noDash sets else [ ]
          else
            [ ];
        cNoDashIdentity = _canonicalCandidatesByIdentity name cNoDash;
        # Digit suffix: "grub" maps to pkgs.grub2, "geoclue" maps to
        # pkgs.geoclue2, "libusb" maps to pkgs.libusb1, and "liblqr" maps to
        # pkgs.liblqr1.
        cDigit =
          if
            allFailed
            && !_hasMatches cXxIdentity
            && !_hasMatches cGtkIdentity
            && !_hasMatches cWkIdentity
            && !_hasMatches cLowerIdentity
            && !_hasMatches cLeadingDigitIdentity
            && !_hasMatches cNoDashIdentity
          then
            lib.findFirst _hasMatches [ ] (
              map (n: _lookupAllInSets (pname + toString n) sets) [
                1
                2
                3
                4
              ]
            )
          else
            [ ];
        cDigitIdentity = _canonicalCandidatesByIdentity name cDigit;
        # Underscore-version attrs: "openssl-1.1.1w" maps to pkgs.openssl_1_1,
        # "libsoup-3.6.6" maps to pkgs.libsoup_3, and
        # "spidermonkey-140.7.1" maps to pkgs.spidermonkey_140.
        cUnderscoreVersion =
          if
            allFailed
            && !_hasMatches cXxIdentity
            && !_hasMatches cGtkIdentity
            && !_hasMatches cWkIdentity
            && !_hasMatches cLowerIdentity
            && !_hasMatches cLeadingDigitIdentity
            && !_hasMatches cNoDashIdentity
            && !_hasMatches cDigitIdentity
          then
            let
              mMajorMinor = builtins.match "${pname}-([0-9]+)[.]([0-9]+).*" name;
              mMajor = builtins.match "${pname}-([0-9]+).*" name;
              attrs =
                if mMajorMinor != null then
                  [
                    "${pname}_${lib.head mMajorMinor}_${builtins.elemAt mMajorMinor 1}"
                    "${pname}_${lib.head mMajorMinor}"
                  ]
                else if mMajor != null then
                  [ "${pname}_${lib.head mMajor}" ]
                else
                  [ ];
            in
            lib.findFirst _hasMatches [ ] (map (attr: _lookupAllInSets attr sets) attrs)
          else
            [ ];
        cUnderscoreVersionIdentity = _canonicalCandidatesByIdentity name cUnderscoreVersion;
        # Dot to dash in attr: "vid.stab" maps to pkgs.vid-stab.
        cDotDash =
          if
            allFailed
            && !_hasMatches cXxIdentity
            && !_hasMatches cGtkIdentity
            && !_hasMatches cWkIdentity
            && !_hasMatches cLowerIdentity
            && !_hasMatches cLeadingDigitIdentity
            && !_hasMatches cNoDashIdentity
            && !_hasMatches cDigitIdentity
            && !_hasMatches cUnderscoreVersionIdentity
          then
            let
              dotDash = lib.replaceStrings [ "." ] [ "-" ] pname;
            in
            if dotDash != pname then _lookupAllInSets dotDash sets else [ ]
          else
            [ ];
        cDotDashIdentity = _canonicalCandidatesByIdentity name cDotDash;
        # Plus to "plus": "memtest86+" maps to pkgs.memtest86plus.
        cPlus =
          if
            allFailed
            && !_hasMatches cXxIdentity
            && !_hasMatches cGtkIdentity
            && !_hasMatches cWkIdentity
            && !_hasMatches cLowerIdentity
            && !_hasMatches cLeadingDigitIdentity
            && !_hasMatches cNoDashIdentity
            && !_hasMatches cDigitIdentity
            && !_hasMatches cUnderscoreVersionIdentity
            && !_hasMatches cDotDashIdentity
          then
            let
              plusName = lib.replaceStrings [ "+" ] [ "plus" ] pname;
            in
            if plusName != pname then _lookupAllInSets plusName sets else [ ]
          else
            [ ];
        cPlusIdentity = _canonicalCandidatesByIdentity name cPlus;
        # Heuristic tiers are ordered from direct/safe matches to progressively
        # lossy attr-name rewrites. Prefer the first identity-preserving tier
        # across the whole cascade before falling back to older pname-only
        # evidence, so a wrong direct attr cannot block a later exact match.
        canonicalCandidates = _firstMatchingCandidates [
          c0Identity
          cPerlIdentity
          cRewriteIdentity
          c1Identity
          c1RewriteIdentity
          c2Identity
          c2RewriteIdentity
          cXxIdentity
          cGtkIdentity
          cWkIdentity
          cLowerIdentity
          cLeadingDigitIdentity
          cNoDashIdentity
          cDigitIdentity
          cUnderscoreVersionIdentity
          cDotDashIdentity
          cPlusIdentity
        ];
        looseCandidates = _firstMatchingCandidates [
          c0
          cPerl
          cRewrite
          c1
          c1Rewrite
          c2
          c2Rewrite
          cXx
          cGtk
          cWk
          cLower
          cLeadingDigit
          cNoDash
          cDigit
          cUnderscoreVersion
          cDotDash
          cPlus
        ];
        candidates =
          if _hasMatches canonicalCandidates then
            canonicalCandidates
          else
            _narrowCandidatesByCanonicalIdentity name looseCandidates;
        # Compare only the metadata we export. If two candidates differ only in
        # internal attrs that never leave this helper, the builder can safely
        # keep the first-pass result instead of treating the name as
        # metadata-distinct.
        metadataVariants = lib.unique (map (_metadataFingerprint name) candidates);
      in
      {
        # ambiguous tracks whether multiple canonically plausible derivations
        # remain. preciseNeeded is narrower: it means those remaining candidates
        # differ in exported metadata, so the builder must not auto-merge them.
        ambiguous = builtins.length candidates > 1;
        preciseNeeded = builtins.length metadataVariants > 1;
        drv = if _hasMatches candidates then lib.head candidates else null;
      };

  # Project only JSON-safe fields from meta. This keeps the helper output
  # stable and makes metadata-equivalence checks compare the same exported
  # surface that the builder later joins into the SBOM.
  filteredMeta = meta: {
    description = meta.description or null;
    homepage = meta.homepage or null;
    unfree = meta.unfree or false;
    position = meta.position or null;
    licenseEntries = _normalizeLicenseEntries (meta.license or null);
    maintainers = map (m: { email = m.email or ""; }) (
      lib.filter lib.isAttrs (meta.maintainers or [ ])
    );
  };

  _metadataFingerprint =
    lookupName: drv:
    builtins.toJSON {
      pname = drv.pname or lookupName;
      version = drv.version or "";
      meta = filteredMeta (drv.meta or { });
    };

  toEntry =
    name:
    let
      match = _findByStoreName name;
      drv = if match == null then null else match.drv;
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
          ambiguous = match.ambiguous;
          preciseNeeded = match.preciseNeeded;
          meta = filteredMeta (drv.meta or { });
        };
      };

in
lib.listToAttrs (lib.filter (x: x != null) (map toEntry names))
