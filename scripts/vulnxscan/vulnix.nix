# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0
{
  nixpkgs ? <nixpkgs>,
  pkgs ? import nixpkgs {},
  lib ? pkgs.lib,
}:
# Use build in upstream nixpkgs
(pkgs.callPackage "${nixpkgs}/pkgs/tools/security/vulnix" {
  inherit (pkgs) python3Packages;
})
.overrideAttrs (
  _old: rec {
    # We use vulnix from 'https://github.com/henrirosten/vulnix' to get
    # vulnix support for runtime-only scan ('-C' command-line option)
    # which is currently not available in released version of vulnix.
    src = pkgs.fetchFromGitHub {
      owner = "henrirosten";
      repo = "vulnix";
      rev = "ad28b2924027a44a9b81493a0f9de1b0e8641005";
      sha256 = "sha256-KXvmnaMjv//zd4aSwu4qmbon1Iyzdod6CPms7LIxeVU=";
    };
    version = "1.10.2.dev0";
    name = "vulnix-${version}";
  }
)
