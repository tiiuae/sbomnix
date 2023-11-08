{
  perSystem = {
    pkgs,
    self',
    ...
  }: let
    pythonPackages = pkgs.python3Packages;
  in {
    packages = {
      nix_visualize = pythonPackages.buildPythonPackage rec {
        version = "1.0.5";
        pname = "nix-visualize";

        src = pkgs.fetchFromGitHub {
          owner = "henrirosten";
          repo = pname;
          rev = "7fedf92eacffd5c42c50f7fec72f61a377c9ccf3";
          hash = "sha256-Z1r8XHszoUnQinl63yXvQG6Czp5HnYNG37AY+EEiT4w=";
        };
        propagatedBuildInputs = with pythonPackages; [
          matplotlib
          networkx
          pygraphviz
          pandas
        ];
      };

      nixupdate = let
        inherit
          (self'.packages)
          repology_cli
          nix_visualize
          requests-ratelimiter
          ;
      in
        pythonPackages.buildPythonPackage rec {
          pname = "nixupdate";
          version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../../VERSION);
          format = "setuptools";

          src = ../../.;

          inherit repology_cli nix_visualize requests-ratelimiter;

          makeWrapperArgs = [
            "--prefix PATH : ${pkgs.lib.makeBinPath [repology_cli nix_visualize]}"
          ];

          propagatedBuildInputs = [
            pkgs.reuse
            requests-ratelimiter
            pythonPackages.beautifulsoup4
            pythonPackages.colorlog
            pythonPackages.graphviz
            pythonPackages.numpy
            pythonPackages.packageurl-python
            pythonPackages.packaging
            pythonPackages.pandas
            pythonPackages.tabulate
            pythonPackages.requests
            pythonPackages.requests-cache
          ];

          postInstall = ''
            install -vD scripts/nixupdate/nix_outdated.py $out/bin/nix_outdated.py
          '';

          pythonImportsCheck = ["sbomnix"];
        };
    };
    apps = {
      nix_outdated = {
        type = "app";
        program = "${self'.packages.nixupdate}/bin/nix_outdated.py";
      };
    };
  };
}
