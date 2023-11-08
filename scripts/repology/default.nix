{
  perSystem = {
    pkgs,
    self',
    ...
  }: let
    pythonPackages = pkgs.python3Packages;
  in {
    packages = {
      pyrate-limiter = pythonPackages.buildPythonPackage rec {
        version = "2.10.0";
        pname = "pyrate-limiter";
        format = "pyproject";

        src = pkgs.fetchFromGitHub {
          owner = "vutran1710";
          repo = "PyrateLimiter";
          rev = "v${version}";
          hash = "sha256-CPusPeyTS+QyWiMHsU0ii9ZxPuizsqv0wQy3uicrDw0=";
        };

        propagatedBuildInputs = with pythonPackages; [
          poetry-core
        ];
      };

      requests-ratelimiter = let
        inherit (self'.packages) pyrate-limiter;
      in
        pythonPackages.buildPythonPackage rec {
          version = "0.4.0";
          pname = "requests-ratelimiter";
          format = "pyproject";

          src = pkgs.fetchFromGitHub {
            owner = "JWCook";
            repo = pname;
            rev = "v${version}";
            hash = "sha256-F9bfcwijyyKzlFKBJAC/5ETc4/hZpPhm2Flckku2z6M=";
          };

          inherit pyrate-limiter;

          propagatedBuildInputs = with pythonPackages; [
            poetry-core
            pyrate-limiter
            requests
          ];
        };

      repology_cli = let
        inherit (self'.packages) requests-ratelimiter;
      in
        pythonPackages.buildPythonPackage rec {
          pname = "repology_cli";
          version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../../VERSION);
          format = "setuptools";

          src = ../../.;

          inherit requests-ratelimiter;

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
            install -vD scripts/repology/repology_cli.py $out/bin/repology_cli.py
            install -vD scripts/repology/repology_cve.py $out/bin/repology_cve.py
          '';

          pythonImportsCheck = ["sbomnix"];

          meta = {
            # TODO add more meta attributes
            mainProgram = "repology_cli.py";
          };
        };
    };
  };
}
