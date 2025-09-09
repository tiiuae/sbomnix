# From: https://github.com/nikstur/bombon/blob/af689bba/LICENSE:
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2022 nikstur
# SPDX-FileCopyrightText: 2025 Technology Innovation Institute (TII)

# This file is heavily inspired by and partially copied from:
# https://github.com/nikstur/bombon/blob/af689bba/nix/buildtime-dependencies.nix

# Usage:
# nix build -f meta.nix --argstr flakeStr github:tiiuae/ghaf#lenovo-x1-carbon-gen11-debug
# nix build -f meta.nix --argstr flakeStr github:tiiuae/ghaf#packages.aarch64-linux.nvidia-jetson-orin-agx-debug
# nix build -f meta.nix --argstr flakeStr nixpkgs#hello
# nix build -f meta.nix --argstr flakeStr 'git+https://github.com/NixOS/patchelf?ref=master'
{
  flakeStr ? null,
}:
let
  split = builtins.match "^([^#]+)#(.*)$" flakeStr;
  flakeRef = if split != null then builtins.elemAt split 0 else flakeStr;
  attr = if split != null then builtins.elemAt split 1 else "default";
  flake = builtins.getFlake flakeRef;
  hasFlakeNixpkgs = flake ? inputs.nixpkgs;
  pkgs = if hasFlakeNixpkgs then import flake.inputs.nixpkgs { } else import flake.outPath { };
  inherit (pkgs) lib;
  path = lib.splitString "." attr;
  paths = [
    path
    (
      [
        "packages"
        builtins.currentSystem
      ]
      ++ path
    )
    (
      [
        "legacyPackages"
        builtins.currentSystem
      ]
      ++ path
    )
  ];
  findRoute =
    route: if (lib.hasAttrByPath route flake) then lib.getAttrFromPath route flake else null;
  notNull = e: e != null;
  allFound = lib.filter notNull (map findRoute paths);
  drv =
    if (builtins.length allFound) > 0 then
      builtins.elemAt allFound 0
    else
      throw "No attribute '${attr}' in flake '${flake}' found";
  drvOutputs =
    drv: if builtins.hasAttr "outputs" drv then map (output: drv.${output}) drv.outputs else [ drv ];
  drvDeps =
    drv:
    lib.mapAttrsToList (
      _k: v:
      if lib.isDerivation v then
        (drvOutputs v)
      else if lib.isList v then
        lib.concatMap drvOutputs (lib.filter lib.isDerivation v)
      else
        [ ]
    ) drv.drvAttrs;
  wrap = drv: {
    key = drv.outPath;
    inherit drv;
  };
  buildtimeDerivations =
    drv0:
    builtins.genericClosure {
      startSet = map wrap (drvOutputs drv0);
      operator = item: map wrap (lib.concatLists (drvDeps item.drv));
    };
  allDrvs = [ drv ];
  allBuildtimeDerivations = lib.flatten (map buildtimeDerivations allDrvs);
  optionalGetAttrs =
    names: attrs: lib.genAttrs (builtins.filter (x: lib.hasAttr x attrs) names) (name: attrs.${name});
  fields =
    drv:
    (optionalGetAttrs [
      "name"
      "pname"
      "version"
      "meta"
    ] drv)
    // lib.optionalAttrs (drv ? src && drv.src ? urls) {
      src = {
        inherit (drv.src) urls;
      }
      // lib.optionalAttrs (drv.src ? outputHash) {
        hash = drv.src.outputHash;
      };
    };
  unformattedJson = pkgs.writeText "${drv.name}-unformatted-meta.json" (
    builtins.toJSON (map (item: (fields item.drv)) allBuildtimeDerivations)
  );
in
if flakeStr == null then
  throw "Missing mandatory argument: 'flakeStr'"
else
  # Format the json output to make it match that of
  # 'nix-env -qa --meta --json -f /path/to/nixpkgs'
  pkgs.runCommand "${drv.name}-meta.json" { } ''
    ${pkgs.jq}/bin/jq 'map( { (.name): . } ) | add' < ${unformattedJson} > "$out"
  ''
