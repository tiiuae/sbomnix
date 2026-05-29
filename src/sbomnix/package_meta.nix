# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# Resolve package metadata for Python-generated attr lookup tiers.  The helper
# scans selected package roots or flake input package roots, then returns metadata
# plus derivation identity.  Python accepts only rows whose drvPath/outPath
# matches an SBOM component exactly.

{
  request ? null,
  pkgs ? null,
}:

let
  requestText = if request != null then request else throw "Missing mandatory argument: 'request'";
  req = builtins.fromJSON requestText;
  flakeref = req.flakeref or null;
  split = if flakeref == null then null else builtins.match "^([^#]+)#(.*)$" flakeref;
  flakeRef = if split != null then builtins.elemAt split 0 else flakeref;
  flake = if flakeRef == null then null else builtins.getFlake flakeRef;
  inherit (req) system;
  nixpkgsPath = req.nixpkgsPath or null;
  lookupKeys = req.lookupKeys or [ ];
  inputRootsOnly = req.inputRootsOnly or false;

  optionals = cond: values: if cond then values else [ ];
  concatMap = f: values: builtins.concatLists (builtins.map f values);
  isAttrs = builtins.isAttrs;
  isDerivation = value: isAttrs value && (value.type or null) == "derivation";
  hasPrefix =
    prefix: str:
    let
      pl = builtins.stringLength prefix;
      sl = builtins.stringLength str;
    in
    pl <= sl && builtins.substring 0 pl str == prefix;
  findFirst =
    pred: default: values:
    if values == [ ] then
      default
    else if pred (builtins.head values) then
      builtins.head values
    else
      findFirst pred default (builtins.tail values);
  hasMatches = values: builtins.length values > 0;
  firstMatchingCandidates = candidateLists: findFirst hasMatches [ ] candidateLists;

  safeAttr =
    attrs: attr:
    let
      res = builtins.tryEval (
        if isAttrs attrs && builtins.hasAttr attr attrs then builtins.getAttr attr attrs else null
      );
    in
    if res.success then res.value else null;

  attrByPath =
    path: attrs:
    if path == [ ] then
      attrs
    else
      let
        value = safeAttr attrs (builtins.head path);
      in
      if value == null then null else attrByPath (builtins.tail path) value;

  importedPkgs =
    if pkgs != null then
      null
    else if nixpkgsPath == null || nixpkgsPath == "" then
      null
    else
      import nixpkgsPath {
        inherit system;
        config.allowAliases = false;
      };

  rootPackages = attrByPath [
    "packages"
    system
  ] flake;
  rootLegacyPackages = attrByPath [
    "legacyPackages"
    system
  ] flake;

  uniqueNames =
    values:
    builtins.attrNames (
      builtins.listToAttrs (
        builtins.map (name: {
          inherit name;
          value = true;
        }) values
      )
    );

  packageSetNames = uniqueNames (
    builtins.filter (name: name != "") (
      concatMap (
        lookup: concatMap (tier: concatMap (candidate: candidate.packageSets) tier) lookup.candidateTiers
      ) lookupKeys
    )
  );

  mkRoot =
    attrSet:
    let
      nestedByName = builtins.listToAttrs (
        builtins.filter (entry: isAttrs entry.value) (
          builtins.map (name: {
            inherit name;
            value = safeAttr attrSet name;
          }) packageSetNames
        )
      );
    in
    {
      base = attrSet;
      inherit nestedByName;
    };

  validRoot = root: isAttrs root.base;
  flakeInputs = attrByPath [ "inputs" ] flake;

  inputRoots =
    if flake == null || !isAttrs flakeInputs then
      [ ]
    else
      concatMap (
        inputName:
        let
          input = safeAttr flakeInputs inputName;
          packages = attrByPath [
            "packages"
            system
          ] input;
          legacyPackages = attrByPath [
            "legacyPackages"
            system
          ] input;
        in
        optionals (isAttrs packages) [
          (mkRoot packages)
        ]
        ++ optionals (isAttrs legacyPackages) [
          (mkRoot legacyPackages)
        ]
      ) (builtins.attrNames flakeInputs);

  explicitPkgsRoots = optionals (isAttrs pkgs) [
    (mkRoot pkgs)
  ];
  flakePackageRoots = builtins.filter validRoot (
    optionals (isAttrs rootPackages) [
      (mkRoot rootPackages)
    ]
    ++ optionals (isAttrs rootLegacyPackages) [
      (mkRoot rootLegacyPackages)
    ]
  );
  importedPkgsRoots = optionals (isAttrs importedPkgs) [
    (mkRoot importedPkgs)
  ];

  baseRoots = builtins.filter validRoot (explicitPkgsRoots ++ flakePackageRoots ++ importedPkgsRoots);
  roots = if inputRootsOnly then builtins.filter validRoot inputRoots else baseRoots;

  packageSetByName = root: name: if name == "" then root.base else root.nestedByName.${name} or null;
  packageSetsByNames =
    root: names:
    builtins.filter (packageSet: packageSet != null) (builtins.map (packageSetByName root) names);

  lookupAttr =
    attr: packageSet:
    let
      res = builtins.tryEval (
        let
          candidate = safeAttr packageSet attr;
        in
        if attr != "" && candidate != null && isDerivation candidate then { drv = candidate; } else null
      );
    in
    if res.success && res.value != null then [ res.value ] else [ ];

  isSimpleOutputName = output: builtins.match "[a-zA-Z0-9][a-zA-Z0-9_+-]*" output != null;

  candidateMatchesSplitOutputName =
    inputName: candidate:
    let
      inherit (candidate) drv;
      drvName = drv.name or null;
      prefix = if drvName == null then null else "${drvName}-";
      suffix =
        if prefix != null && hasPrefix prefix inputName then
          builtins.substring (builtins.stringLength prefix) (
            builtins.stringLength inputName - builtins.stringLength prefix
          ) inputName
        else
          null;
      outputs = builtins.filter (output: output != "out") (drv.outputs or [ "out" ]);
    in
    suffix != null && suffix != "" && isSimpleOutputName suffix && builtins.elem suffix outputs;

  canonicalCandidatesByIdentity =
    inputName: candidates:
    let
      exactNameMatches = builtins.filter (
        candidate: (candidate.drv.name or null) == inputName
      ) candidates;
      splitOutputMatches = builtins.filter (
        candidate: candidateMatchesSplitOutputName inputName candidate
      ) candidates;
    in
    if hasMatches exactNameMatches then
      exactNameMatches
    else if hasMatches splitOutputMatches then
      splitOutputMatches
    else
      [ ];

  candidateMatchesExpectedPnameOrName =
    inputName: expectedPname: candidate:
    (candidate.drv.name or null) == inputName || (candidate.drv.pname or null) == expectedPname;

  candidatePlausible =
    inputName: expectedPname: expectedVersion: candidate:
    let
      inherit (candidate) drv;
      drvName = drv.name or null;
      drvPname = drv.pname or null;
      drvVersion = drv.version or null;
      versionMatches = expectedVersion == "" || drvVersion == expectedVersion;
    in
    drvName == inputName
    || candidateMatchesSplitOutputName inputName candidate
    || (expectedPname != "" && drvPname == expectedPname && versionMatches);

  narrowPlausible =
    inputName: expectedPname: expectedVersion: candidates:
    let
      plausible = builtins.filter (candidatePlausible inputName expectedPname expectedVersion) candidates;
    in
    if hasMatches plausible then plausible else [ ];

  lookupCandidate =
    root: lookup: candidate:
    let
      inputName = lookup.name or "";
      expectedPname = lookup.pname or "";
      matches = concatMap (lookupAttr candidate.attr) (packageSetsByNames root candidate.packageSets);
    in
    if candidate.requirePnameOrName or false then
      builtins.filter (candidateMatchesExpectedPnameOrName inputName expectedPname) matches
    else
      matches;

  lookupTier =
    root: lookup: tier:
    concatMap (lookupCandidate root lookup) tier;

  findByLookup =
    root: lookup:
    let
      name = lookup.name or "";
      pname = lookup.pname or "";
      version = lookup.version or "";
      tiers = lookup.candidateTiers;
      tierCandidates = builtins.map (lookupTier root lookup) tiers;
      canonicalCandidateLists = builtins.map (canonicalCandidatesByIdentity name) tierCandidates;
      canonicalCandidates =
        if lookup.collectAllCanonical or false then
          builtins.concatLists canonicalCandidateLists
        else
          firstMatchingCandidates canonicalCandidateLists;
      plausibleCandidates = firstMatchingCandidates (
        builtins.map (narrowPlausible name pname version) tierCandidates
      );
    in
    # Prefer matches whose derivation/output identity explains the input
    # component name.  Pname/version matches are a fallback for packages whose
    # attr name cannot be inferred exactly.
    if hasMatches canonicalCandidates then canonicalCandidates else plausibleCandidates;

  normalizedIdentifiers =
    meta:
    let
      hasNonEmptyString = value: builtins.isString value && value != "";
      hasNonEmptyList = value: builtins.isList value && value != [ ];
      metaIdentifiers = safeAttr meta "identifiers";
      identifiers = if isAttrs metaIdentifiers then metaIdentifiers else { };
      identifiersV1Value = safeAttr identifiers "v1";
      identifiersV1 = if isAttrs identifiersV1Value then identifiersV1Value else { };
      topLevelPossibleCPEs = safeAttr meta "possibleCPEs";
      nestedPossibleCPEs = safeAttr identifiers "possibleCPEs";
      nestedV1PossibleCPEs = safeAttr identifiersV1 "possibleCPEs";
      possibleCPEs =
        if hasNonEmptyList topLevelPossibleCPEs then
          topLevelPossibleCPEs
        else if hasNonEmptyList nestedPossibleCPEs then
          nestedPossibleCPEs
        else if hasNonEmptyList nestedV1PossibleCPEs then
          nestedV1PossibleCPEs
        else if builtins.isList topLevelPossibleCPEs then
          topLevelPossibleCPEs
        else if builtins.isList nestedPossibleCPEs then
          nestedPossibleCPEs
        else if builtins.isList nestedV1PossibleCPEs then
          nestedV1PossibleCPEs
        else
          [ ];
      metaCPE = safeAttr meta "cpe";
      identifiersCPE = safeAttr identifiers "cpe";
      identifiersV1CPE = safeAttr identifiersV1 "cpe";
    in
    {
      cpe =
        if hasNonEmptyString metaCPE then
          metaCPE
        else if hasNonEmptyString identifiersCPE then
          identifiersCPE
        else if hasNonEmptyString identifiersV1CPE then
          identifiersV1CPE
        else
          null;
      possibleCPEs = builtins.filter (
        candidate: isAttrs candidate && safeAttr candidate "cpe" != null
      ) possibleCPEs;
    };

  filteredMeta =
    meta:
    let
      identifiers = normalizedIdentifiers meta;
    in
    {
      description = meta.description or null;
      homepage = meta.homepage or null;
      unfree = meta.unfree or false;
      position = meta.position or null;
      cpe = identifiers.cpe;
      possibleCPEs = identifiers.possibleCPEs;
      license = meta.license or { };
      maintainers = builtins.map (maintainer: { email = maintainer.email or ""; }) (
        builtins.filter isAttrs (meta.maintainers or [ ])
      );
    };

  drvOutputs =
    drv: if drv ? outputs then builtins.map (output: drv.${output}) drv.outputs else [ drv ];

  field =
    fallbackDrv: drv: name: default:
    let
      value = safeAttr drv name;
      fallbackValue = safeAttr fallbackDrv name;
    in
    if value != null then
      value
    else if fallbackValue != null then
      fallbackValue
    else
      default;

  fields = fallbackDrv: drv: {
    path = field fallbackDrv drv "outPath" null;
    drvPath = field fallbackDrv drv "drvPath" null;
    name = field fallbackDrv drv "name" "";
    pname = field fallbackDrv drv "pname" "";
    version = field fallbackDrv drv "version" "";
    meta = filteredMeta (field fallbackDrv drv "meta" { });
  };

  rowsForCandidate =
    candidate:
    let
      rawRows = builtins.map (fields candidate.drv) (drvOutputs candidate.drv);
      forced = builtins.tryEval (builtins.deepSeq rawRows rawRows);
    in
    if forced.success then forced.value else [ ];

  rowsForLookupInRoot =
    root: lookup:
    let
      candidatesTry = builtins.tryEval (findByLookup root lookup);
      candidates = if candidatesTry.success then candidatesTry.value else [ ];
    in
    concatMap rowsForCandidate candidates;

  rowsForLookup = lookup: concatMap (root: rowsForLookupInRoot root lookup) roots;

in
{
  derivations = concatMap rowsForLookup lookupKeys;
}
