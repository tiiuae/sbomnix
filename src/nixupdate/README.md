<!--
SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)

SPDX-License-Identifier: CC-BY-SA-4.0
-->

Table of Contents
=================

* [Getting Started](#getting-started)
   * [Running as Nix Flake](#running-as-nix-flake)
   * [Running from Nix Development Shell](#running-from-nix-development-shell)
   * [Example Target](#example-target)
* [nix_outdated](#nix_outdated)

# Getting Started
## Running as Nix Flake
`nix_outdated.py` can be run as a [Nix flake](https://nixos.wiki/wiki/Flakes) from the `tiiuae/sbomnix` repository:
```bash
# '--' signifies the end of argument list for `nix`.
# '--help' is the first argument to `nix_outdated`
$ nix run github:tiiuae/sbomnix#nix_outdated -- --help
```

or from a local repository:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ nix run .#nix_outdated -- --help
```

## Running from Nix Development Shell

If you have nix flakes enabled, run:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ nix develop
```

You can also use `nix-shell` to enter the development shell:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ nix-shell
```

From the development shell, you can run `nix_outdated.py` as follows:
```bash
# Run nix_outdated from nix devshell:
$ scripts/nixupdate/nix_outdated.py --help
```


## Example Target
We use Nix package `git` as an example target.
To print `git` out-path on your local system, try something like:
```bash
$ nix eval -f '<nixpkgs>' 'git.outPath'
"/nix/store/2853v0cidl7jww2hs1mlkg0i372mk368-git-2.39.2"
```

# nix_outdated
`nix_outdated` is a command line tool to list outdated nix dependencies for given target nix out path. By default, the script outputs runtime dependencies for the given nix out path that appear outdated in nixpkgs 'nix_unstable' channel - the list of output packages would potentially need a PR to update the package in nixpkgs to the latest upstream release version specified in the output table column 'version_upstream'. The list of output packages is in priority order based on how many other packages depend on the potentially outdated package.

Below command finds runtime dependencies of `git` that would have an update in the package's upstream repository based on repology, but the latest release version is not available in nix unstable:

```bash
# In nix devshell
$ scripts/nixupdate/nix_outdated.py /nix/store/2853v0cidl7jww2hs1mlkg0i372mk368-git-2.39.2
INFO     Generating SBOM for target '/nix/store/2853v0cidl7jww2hs1mlkg0i372mk368-git-2.39.2'
INFO     Loading runtime dependencies referenced by '/nix/store/2853v0cidl7jww2hs1mlkg0i372mk368-git-2.39.2'
INFO     Using SBOM '/tmp/nixdeps_uejjwppb.cdx.json'
INFO     Running repology_cli
INFO     Using repology out: '/tmp/repology_i1ycaa7g.csv'
INFO     Running nix-visualize
INFO     Using nix-visualize out: '/tmp/nix-visualize_tl6zogfj.csv'
INFO     Writing console report
INFO     Dependencies that need update in nixpkgs (in priority order based on how many other packages depend on the potentially outdated package):

|  priority  | nix_package        | version_local   | version_nixpkgs   | version_upstream      |
|------------+--------------------+-----------------+-------------------+-----------------------|
|     9      | libidn2            | 2.3.2           | 2.3.2             | 2.3.4                 |
|     8      | glibc              | 2.35-224        | 2.35-224          | 2.37                  |
|     5      | perl:uri           | 5.05            | 5.05              | 5.17                  |
|     4      | perl:http-message  | 6.26            | 6.26              | 6.44                  |
|     4      | openssl            | 3.0.8           | 3.0.8             | 3.1.0                 |
|     3      | perl:html-parser   | 3.75            | 3.75              | 3.81                  |
|     3      | perl:try-tiny      | 0.30            | 0.30              | 0.31                  |
|     3      | perl:mozilla-ca    | 20200520        | 20200520          | 20221114;20221114.0.0 |
|     2      | perl:digest-hmac   | 1.03            | 1.03              | 1.04                  |
|     2      | sqlite             | 3.40.1          | 3.41.0            | 3.41.1                |
|     2      | perl:fcgi          | 0.79            | 0.79              | 0.82                  |
|     2      | perl:net-http      | 6.19            | 6.19              | 6.22                  |
|     2      | perl:io-socket-ssl | 2.068           | 2.068             | 2.081;2.81.0          |
|     2      | perl:file-listing  | 6.14            | 6.14              | 6.15                  |
|     2      | perl:http-daemon   | 6.14            | 6.14              | 6.16                  |
|     2      | perl:http-cookies  | 6.09            | 6.09              | 6.10;6.10.0           |
|     2      | perl:cgi           | 4.51            | 4.51              | 4.56                  |
|     2      | nghttp2            | 1.51.0          | 1.51.0            | 1.52.0                |
|     2      | perl:test-fatal    | 0.016           | 0.016             | 0.017;0.17.0          |
|     2      | perl:test-needs    | 0.002006        | 0.002006          | 0.002010              |
|     1      | perl:libnet        | 3.12            | 3.12              | 3.14                  |
|     1      | git                | 2.39.2          | 2.39.2            | 2.40.0                |
|     1      | gettext            | 0.21            | 0.21              | 0.21.1                |
|     1      | perl:libwww-perl   | 6.67            | 6.67              | 6.68                  |


INFO     Wrote: nix_outdated.csv
```

As an example, the first row in the above output table means that:
- `libidn2` in nix unstable is not up-to-date with what repology.org knows is the package's newest upstream version.
- `libidn2` is on the top of the table, as it has the highest priority among the listed outdated packages. The priority is based on how many other packages depend on the given outdated package. This datapoint is based on [nix-visualize](https://github.com/craigmbooth/nix-visualize) with the following change to allow using nix-visualize for large projects, as well allow post-processing the nix-visualize output data in textual format: https://github.com/craigmbooth/nix-visualize/pull/8. The value of the `priority` column is directly the `level` value determined by [nix-visualize](https://github.com/craigmbooth/nix-visualize). For full description of the `level` values, see nix-visualize documentation: https://github.com/craigmbooth/nix-visualize#vertical-positioning.
- `libidn2` local version is 2.3.2.
- `libidn2` newest version in nix unstable is 2.3.2 (based on repology.org).
- `libidn2` newest release version in the package's upstream repository is 2.3.4 (based on repology.org).
- `libidn2` is considered outdated, because the version string in `version_upstream` is later than the version string in `version_nixpkgs`.
