# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

# Resolve package metadata for SBOM components by derivation identity.
#
# Each lookup carries the drvPath/outPath identity of the components it stands
# for.  Derivations are found in two ways:
#
#   1. Walking the derivation values reachable from the flake target through
#      derivation attributes.  This finds exactly the derivations the target
#      was built from, including overridden and bootstrap packages.
#   2. Looking up Python-generated attr name candidates in the package roots
#      for components the walk did not reach, such as dependencies referenced
#      only through string context.
#
# Only derivations whose drvPath or outPath equals a requested component path
# are returned.

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
  nixpkgsPath = req.nixpkgsPath or null;
  lookupKeys = req.lookupKeys or [ ];
  targetAttrPaths = req.targetAttrPaths or [ ];
  searchInputs = req.searchInputs or true;

  optionals = cond: values: if cond then values else [ ];
  concatMap = f: values: builtins.concatLists (builtins.map f values);
  isAttrs = builtins.isAttrs;
  isDerivation = value: isAttrs value && (value.type or null) == "derivation";
  hasMatches = values: builtins.length values > 0;
  try =
    default: value:
    let
      res = builtins.tryEval value;
    in
    if res.success then res.value else default;
  hasPrefix =
    prefix: str:
    let
      pl = builtins.stringLength prefix;
      sl = builtins.stringLength str;
    in
    pl <= sl && builtins.substring 0 pl str == prefix;

  safeAttr =
    attrs: attr:
    try null (if isAttrs attrs && builtins.hasAttr attr attrs then attrs.${attr} else null);

  attrByPath =
    path: attrs:
    if path == [ ] then
      attrs
    else
      let
        value = safeAttr attrs (builtins.head path);
      in
      if value == null then null else attrByPath (builtins.tail path) value;

  # Derivation identity ######################################################

  drvOutputs =
    drv:
    if drv ? outputs then
      builtins.filter isAttrs (builtins.map (output: drv.${output} or null) drv.outputs)
    else
      [ drv ];

  storePaths =
    values: builtins.map builtins.unsafeDiscardStringContext (builtins.filter builtins.isString values);

  # A walk node: the derivation with its drvPath and output paths, or nothing
  # when the derivation does not evaluate.
  drvNodes =
    drv:
    let
      identity = {
        drvPath = storePaths [ (drv.drvPath or null) ];
        outPaths = storePaths (builtins.map (output: output.outPath or null) (drvOutputs drv));
      };
      forced = try null (builtins.deepSeq identity identity);
      paths = forced.drvPath ++ forced.outPaths;
    in
    optionals (forced != null && hasMatches paths) [
      {
        key = builtins.head paths;
        inherit drv paths;
        inherit (forced) outPaths;
        drvPath = if hasMatches forced.drvPath then builtins.head forced.drvPath else null;
      }
    ];

  indexByPath =
    nodes:
    builtins.listToAttrs (
      concatMap (
        node:
        builtins.map (path: {
          name = path;
          value = node;
        }) node.paths
      ) nodes
    );

  # Derivation graph walk ####################################################

  # Derivation values nested in a derivation attribute value.  Attribute sets
  # only nest further in structured attrs; ones that coerce to a store path,
  # such as flake inputs, are not package containers.
  drvsIn =
    value:
    if isDerivation value then
      [ value ]
    else if builtins.isList value then
      concatMap drvsIn value
    else if isAttrs value && !(value ? outPath) && !(value ? __toString) then
      concatMap drvsIn (builtins.attrValues value)
    else
      [ ];

  # Instantiating a derivation forces all of its attributes, so walking them
  # does not evaluate anything the derivation itself did not need.
  drvDeps = drv: try [ ] (concatMap drvsIn (builtins.attrValues (drv.drvAttrs or { })));

  closure =
    nodes:
    builtins.genericClosure {
      startSet = nodes;
      operator = node: concatMap drvNodes (drvDeps node.drv);
    };

  targetDrvs =
    let
      found = builtins.filter isDerivation (builtins.map (path: attrByPath path flake) targetAttrPaths);
    in
    optionals (hasMatches found) [ (builtins.head found) ];

  targetNodes = closure (concatMap drvNodes targetDrvs);

  # A walked derivation without a description does not stand in for the
  # package: the roots can hold the same derivation with full metadata, as for
  # an output of a derivation whose meta attribute was merged in afterwards.
  hasDescription = node: builtins.isString (attrByPath [ "meta" "description" ] node.drv);
  targetIndex = indexByPath (builtins.filter hasDescription targetNodes);

  # Package roots ############################################################

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

  # A root is one or more package sets that are searched together: each attr
  # holds the list of its values in the sets.
  mkRoot =
    attrSets:
    let
      merge = sets: builtins.zipAttrsWith (_: values: values) (builtins.filter isAttrs sets);
    in
    {
      base = merge attrSets;
      nestedByName = builtins.listToAttrs (
        builtins.map (name: {
          inherit name;
          value = merge (builtins.map (attrSet: safeAttr attrSet name) attrSets);
        }) packageSetNames
      );
    };

  flakeOutput =
    output: system: flakeValue:
    attrByPath [ output system ] flakeValue;
  packageRoots =
    attrSets: builtins.map (attrSet: mkRoot [ attrSet ]) (builtins.filter isAttrs attrSets);

  flakeInputs = attrByPath [ "inputs" ] flake;

  # Package roots for one system.  The base roots are searched first; the
  # package outputs of flake inputs only for what the base roots do not have.
  rootsFor =
    system:
    let
      importedPkgs =
        if pkgs != null || nixpkgsPath == null || nixpkgsPath == "" then
          null
        else
          import nixpkgsPath {
            inherit system;
            config.allowAliases = false;
          };
      inputs = builtins.map (safeAttr flakeInputs) (builtins.attrNames flakeInputs);
    in
    {
      base = packageRoots [
        pkgs
        (flakeOutput "packages" system flake)
        (flakeOutput "legacyPackages" system flake)
        importedPkgs
      ];
      inputs =
        if !searchInputs || !isAttrs flakeInputs then
          [ ]
        else
          [
            (mkRoot (
              builtins.map (flakeOutput "packages" system) inputs
              ++ builtins.map (flakeOutput "legacyPackages" system) inputs
            ))
          ];
    };

  rootsBySystem = builtins.listToAttrs (
    builtins.map (system: {
      name = system;
      value = rootsFor system;
    }) (uniqueNames (builtins.map (lookup: lookup.system) lookupKeys))
  );

  # Attr name lookup #########################################################

  packageSetByName = root: name: if name == "" then root.base else root.nestedByName.${name} or null;

  lookupAttr =
    attr: packageSet:
    let
      values = safeAttr packageSet attr;
    in
    optionals (attr != "" && values != null) (
      builtins.filter (drv: try false (isDerivation drv)) values
    );

  candidateDrvs =
    root: candidate:
    concatMap (lookupAttr candidate.attr) (
      builtins.filter (packageSet: packageSet != null) (
        builtins.map (packageSetByName root) candidate.packageSets
      )
    );

  isSimpleOutputName = output: builtins.match "[a-zA-Z0-9][a-zA-Z0-9_+-]*" output != null;

  matchesSplitOutputName =
    inputName: drv:
    let
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

  # Cheap name checks that keep unrelated candidates from being instantiated.
  drvPlausible =
    lookup: drv:
    let
      versionMatches = lookup.version == "" || (drv.version or null) == lookup.version;
    in
    (drv.name or null) == lookup.name
    || matchesSplitOutputName lookup.name drv
    || (lookup.pname != "" && (drv.pname or null) == lookup.pname && versionMatches);

  nodeMatches = paths: node: builtins.any (path: builtins.elem path paths) node.paths;

  # Candidate derivations whose identity matches one of the wanted paths.
  tierMatches =
    lookup: paths: root: tier:
    builtins.filter (nodeMatches paths) (
      concatMap drvNodes (
        builtins.filter (drv: try false (drvPlausible lookup drv)) (concatMap (candidateDrvs root) tier)
      )
    );

  # Search the roots tier by tier until every component has a match.
  # Same-named components can come from different roots or tiers.  The roots
  # are not evaluated when there is nothing to search for.
  searchRoots =
    lookup: components: roots:
    let
      start = {
        matches = [ ];
        remaining = components;
      };
      searches = concatMap (
        root: builtins.map (tier: paths: tierMatches lookup paths root tier) lookup.candidateTiers
      ) roots;
      step =
        state: search:
        if state.remaining == [ ] then
          state
        else
          let
            found = search (builtins.concatLists state.remaining);
          in
          {
            matches = state.matches ++ found;
            remaining = builtins.filter (paths: !(builtins.any (nodeMatches paths) found)) state.remaining;
          };
    in
    if components == [ ] then start else builtins.foldl' step start searches;

  # Search package roots only for components the target walk did not reach,
  # and the roots of flake inputs only for what the base roots do not have.
  lookupNodes =
    lookup:
    let
      unwalked = builtins.filter (
        paths: !(builtins.any (path: builtins.hasAttr path targetIndex) paths)
      ) lookup.components;
      roots = rootsBySystem.${lookup.system};
      base = searchRoots lookup unwalked roots.base;
      inputs = searchRoots lookup base.remaining roots.inputs;
    in
    base.matches ++ inputs.matches;

  # Derivations found by name can depend on packages that no attr name leads
  # to, so walk them as well.
  nodes = closure (concatMap lookupNodes lookupKeys ++ targetNodes);

  wantedPaths = builtins.listToAttrs (
    concatMap (
      lookup:
      builtins.map (path: {
        name = path;
        value = null;
      }) (builtins.concatLists lookup.components)
    ) lookupKeys
  );
  wantedNodes = builtins.filter (
    node: builtins.any (path: builtins.hasAttr path wantedPaths) node.paths
  ) nodes;

  # Metadata rows ############################################################

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

  nodeRows =
    node:
    let
      meta = safeAttr node.drv "meta";
      row = {
        inherit (node) drvPath outPaths;
        name = node.drv.name or "";
        pname = node.drv.pname or "";
        version = node.drv.version or "";
        meta = filteredMeta (if isAttrs meta then meta else { });
      };
      forced = builtins.tryEval (builtins.deepSeq row row);
    in
    optionals forced.success [ forced.value ];

in
{
  derivations = concatMap nodeRows wantedNodes;
}
