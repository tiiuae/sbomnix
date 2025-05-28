<!--
SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Getting Started
To get started, follow the [Getting Started](../README.md#getting-started) section from the main [README](../README.md).

As an example, to run the [`nixmeta`](../src/nixmeta/main.py) from the `tiiuae/sbomnix` repository:
```bash
# '--' signifies the end of argument list for `nix`.
# '--help' is the first argument to `nixmeta`
$ nix run github:tiiuae/sbomnix#nixmeta -- --help
```

# nixmeta
[`nixmeta`](../src/nixmeta/main.py) is a command line tool to summarize nixpkgs meta-attributes from the given nixpkgs version. The output is written to a csv file. Nixpkgs version is specified with [`flakeref`](https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-flake#flake-references). As an example, `--flakeref=github:NixOS/nixpkgs?ref=master` would make `nixmeta` output the meta-attributes from the nixpkgs version in the [master](https://github.com/NixOS/nixpkgs/tree/master) branch. Similarly, `--flakeref=github:NixOS/nixpkgs?ref=release-23.11` would output the meta-attributes from the nixpkgs version in the [release-23.11](https://github.com/NixOS/nixpkgs/tree/release-23.11) branch. Note that `--flakeref` does not necessarily have to reference `github:NixOS/nixpkgs` but any flakeref or even `NIX_ENV` environment variable can be used to specify the nixpkgs version. As an example, `--flakeref=github:tiiuae/sbomnix` would make `nixmeta` output the meta-attributes from the nixpkgs version [pinned by the sbomnix flake](https://github.com/tiiuae/sbomnix/blob/c243db5272fb01c4d97cbbb01a095ae514cd2dcb/flake.lock#L68) in its default branch.

As an example, below command outputs nixpkgs meta-attributes from the nixpkgs version pinned by flake `github:NixOS/nixpkgs?ref=master`:

```bash
$ ./src/nixmeta/main.py --flakeref=github:NixOS/nixpkgs?ref=master
INFO     Finding meta-info for nixpkgs pinned in flake: github:NixOS/nixpkgs?ref=master
INFO     Wrote: /home/foo/sbomnix-fork/nixmeta.csv
```

Output summarizes the meta-attributes of all the target nixpkgs packages enumerated by `nix-env --query --available`.
For each package, the output includes the following details:

```bash
$ head -n2 nixmeta.csv | csvlook
| name       | pname | version | meta_homepage        | meta_unfree | meta_license_short               | meta_license_spdxid                    | meta_maintainers_email |
| ---------- | ----- | ------- | -------------------- | ----------- | -------------------------------- | -------------------------------------- | ---------------------- |
| 0ad-0.0.26 | 0ad   | 0.0.26  | https://play0ad.com/ |       False | gpl2;lgpl21;mit;cc-by-sa-30;zlib | GPL-2.0;LGPL-2.1;MIT;CC-BY-SA-3.0;Zlib | nixpkgs@cvpetegem.be   |

```
