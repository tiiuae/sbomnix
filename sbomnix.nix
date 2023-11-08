{
  perSystem = {
    pkgs,
    self',
    ...
  }: let
    pythonPackages = pkgs.python3Packages;
  in {
    packages.sbomnix = pythonPackages.buildPythonPackage rec {
      pname = "sbomnix";
      version = pkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);
      format = "setuptools";

      src = ./.;
      makeWrapperArgs = [
        "--prefix PATH : ${pkgs.lib.makeBinPath [pkgs.nix pkgs.graphviz]}"
      ];

      propagatedBuildInputs = [
        pkgs.reuse
        pythonPackages.colorlog
        pythonPackages.graphviz
        pythonPackages.numpy
        pythonPackages.packageurl-python
        pythonPackages.packaging
        pythonPackages.pandas
        pythonPackages.requests
        pythonPackages.tabulate
      ];
      pythonImportsCheck = ["sbomnix"];
    };
    apps.nixgraph = {
      type = "app";
      program = "${self'.packages.sbomnix}/bin/nixgraph";
    };
  };
}
