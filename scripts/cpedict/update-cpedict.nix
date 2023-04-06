# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  pkgs ? import <nixpkgs> {},
}:

pkgs.stdenv.mkDerivation rec {
  doCheck = true;
  pname = "update-cpedict.sh";
  version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../../VERSION);
  src = ./update-cpedict.sh;

  path = pkgs.lib.makeBinPath ([
    pkgs.coreutils
    pkgs.curl
    pkgs.gnugrep
    pkgs.gnused
    pkgs.gzip
  ]);

  checkInputs = [ pkgs.shellcheck ];
  buildInputs = [ pkgs.bash ];
  unpackPhase = ''
    cp ${src} ${pname}
  '';
  checkPhase = ''
    shellcheck ${pname}
  '';
  installPhase = ''
    mkdir -p $out/bin
    cp ${pname} $out/bin/${pname}
    chmod +x $out/bin/${pname}
  '';
}
