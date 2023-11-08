{lib, ...}: {
  perSystem = {self', ...}: {
    checks =
      # merge in the package derivations to force a build of all packages during a `nix flake check`
      with lib; mapAttrs' (n: nameValuePair "package-${n}") self'.packages;
  };
}
