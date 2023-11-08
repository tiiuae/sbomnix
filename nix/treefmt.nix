{inputs, ...}: {
  imports = with inputs; [
    flake-root.flakeModule
    treefmt-nix.flakeModule
  ];
  perSystem = {
    config,
    pkgs,
    ...
  }: {
    treefmt.config = {
      package = pkgs.treefmt;
      inherit (config.flake-root) projectRootFile;

      programs = {
        alejandra.enable = true; # nix formatter https://github.com/kamadorueda/alejandra
        deadnix.enable = true; # removes dead nix code https://github.com/astro/deadnix
        statix.enable = true; # prevents use of nix anti-patterns https://github.com/nerdypepper/statix
      };
    };

    formatter = config.treefmt.build.wrapper;
  };
}
