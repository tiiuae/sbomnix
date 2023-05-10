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
* [nix_secupdates](#nix_secupdates)

# Getting Started
## Running as Nix Flake
`nix_outdated.py` and `nix_secupdates.py` can be run as a [Nix flake](https://nixos.wiki/wiki/Flakes) from the `tiiuae/sbomnix` repository:
```bash
# '--' signifies the end of argument list for `nix`.
# '--help' is the first argument to `nix_outdated`
$ nix run github:tiiuae/sbomnix#nix_outdated -- --help
```

or from a local repository:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ nix run .#nix_secupdates -- --help
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

From the development shell, you can run `nix_outdated.py` or `nix_secupdates.py` as follows:
```bash
# Run nix_outdated from nix devshell:
$ scripts/nixupdate/nix_outdated.py --help

# Run nix_secupdates from nix devshell:
$ scripts/nixupdate/nix_secupdates.py --help
```


## Example Target
We use Nix package `git` as an example target.
To install git and print out its out-path on your local system, try something like:
```bash
$ nix-shell -p git --run exit && nix eval -f '<nixpkgs>' 'git.outPath'
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


# nix_secupdates
`nix_secupdates` is a command line tool that demonstrates finding and classifying potential security updates for given nix target or any of its dependencies.

Below command finds security issues for runtime dependencies of `firefox`, and classifies the update availability for each vulnerability:

```bash
# In devshell
scripts/nixupdate/nix_secupdates.py /nix/store/pidpcf621di8xkp41b0anb61rjfalh9w-firefox-112.0
INFO     Running vulnxscan for target '/nix/store/pidpcf621di8xkp41b0anb61rjfalh9w-firefox-112.0'
INFO     Using vulnxscan result: '/tmp/secupdates_vulnxscan_h4pw7a6g.csv'
INFO     Querying repology
INFO     Console report

Potential vulnerabilities impacting version_local, with suggested update actions:

|                     |                | version | version | version  |                                      |
| vuln_id             |  package       | local   | nixpkgs | upstream | classify                             |
|---------------------+----------------+---------+---------+----------+--------------------------------------|
| CVE-2023-29383      |  shadow        | 4.13    | 4.13    | 4.13     | fix_not_available                    |
| CVE-2023-27371      |  libmicrohttpd | 0.9.71  | 0.9.72  | 0.9.76   | fix_update_to_version_upstream       |
| CVE-2023-1916       |  libtiff       | 4.5.0   |         |          | err_missing_repology_version         |
| CVE-2023-0466       |  openssl       | 3.0.8   | 3.0.8   | 3.1.0    | err_not_vulnerable_based_on_repology |
| CVE-2023-0465       |  openssl       | 3.0.8   | 3.0.8   | 3.1.0    | err_not_vulnerable_based_on_repology |
| CVE-2023-0464       |  openssl       | 3.0.8   | 3.0.8   | 3.1.0    | err_not_vulnerable_based_on_repology |
| OSV-2023-323        |  harfbuzz      | 7.1.0   | 7.1.0   | 7.1.0    | err_not_vulnerable_based_on_repology |
| OSV-2023-222        |  harfbuzz      | 7.1.0   | 7.1.0   | 7.1.0    | err_not_vulnerable_based_on_repology |
| OSV-2023-170        |  harfbuzz      | 7.1.0   | 7.1.0   | 7.1.0    | err_not_vulnerable_based_on_repology |
| OSV-2023-137        |  harfbuzz      | 7.1.0   | 7.1.0   | 7.1.0    | err_not_vulnerable_based_on_repology |
| CVE-2022-48281      |  libtiff       | 4.5.0   |         |          | err_missing_repology_version         |
| CVE-2022-47021      |  opusfile      | 0.12    | 0.12    | 0.12     | fix_not_available                    |
| CVE-2022-28506      |  giflib        | 5.2.1   | 5.2.1   | 5.2.1    | fix_not_available                    |
| CVE-2022-28321      |  linux-pam     | 1.5.2   |         |          | err_missing_repology_version         |
| CVE-2022-26691      |  cups          | 2.4.2   | 2.4.2   | 2.4.2    | fix_not_available                    |
| CVE-2022-3965       |  ffmpeg        | 5.1.2   | 6.0     | 6.0      | fix_update_to_version_nixpkgs        |
| CVE-2022-3964       |  ffmpeg        | 5.1.2   | 6.0     | 6.0      | fix_update_to_version_nixpkgs        |
| CVE-2022-3219       |  gnupg         | 2.4.0   | 2.4.0   | 2.4.0    | err_not_vulnerable_based_on_repology |
| OSV-2022-1168       |  gstreamer     | 1.20.3  | 1.20.3  | 1.22.2   | err_not_vulnerable_based_on_repology |
| OSV-2022-1089       |  gstreamer     | 1.20.3  | 1.20.3  | 1.22.2   | err_not_vulnerable_based_on_repology |
| OSV-2022-908        |  bluez         | 5.66    | 5.66    | 5.66     | err_not_vulnerable_based_on_repology |
| OSV-2022-859        |  bluez         | 5.66    | 5.66    | 5.66     | err_not_vulnerable_based_on_repology |
| GHSA-6898-wx94-8jq8 |  libnotify     | 0.8.2   | 0.8.2   | 0.8.2    | err_not_vulnerable_based_on_repology |
| CVE-2021-26720      |  avahi         | 0.8     | 0.8     | 0.8      | fix_not_available                    |
| CVE-2021-3468       |  avahi         | 0.8     | 0.8     | 0.8      | fix_not_available                    |
| OSV-2021-777        |  libxml2       | 2.10.3  | 2.10.3  | 2.10.4   | err_not_vulnerable_based_on_repology |
| CVE-2020-24490      |  bluez         | 5.66    | 5.66    | 5.66     | err_not_vulnerable_based_on_repology |
| CVE-2019-6462       |  cairo         | 1.16.0  | 1.16.0  | 1.16.0   | fix_not_available                    |
| CVE-2019-6461       |  cairo         | 1.16.0  | 1.16.0  | 1.16.0   | fix_not_available                    |
| CVE-2018-7263       |  libmad        | 0.15.1b | 0.15.1b | 0.16.3   | err_not_vulnerable_based_on_repology |
| CVE-2018-6553       |  cups          | 2.4.2   | 2.4.2   | 2.4.2    | err_not_vulnerable_based_on_repology |
| CVE-2017-6839       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-6838       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-6837       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-6836       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-6835       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-6834       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-6833       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-6832       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-6831       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-6830       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-6829       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-6828       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-6827       |  audiofile     | 0.3.6   | 0.3.6   | 0.3.6    | fix_not_available                    |
| CVE-2017-5436       |  graphite2     | 1.3.14  | 1.3.14  | 1.3.14   | err_not_vulnerable_based_on_repology |
| CVE-2016-2781       |  coreutils     | 9.1     | 9.1     | 9.3      | fix_not_available                    |
| CVE-2015-7313       |  libtiff       | 4.5.0   |         |          | err_missing_repology_version         |

```

As an example, the output table states the following:
- Package `shadow`, which is a runtime dependency of firefox, is potentially vulnerable to CVE-2023-29383.
- The dependency package `shadow` local version is 4.13. Based on repology.org, version 4.13 is also the latest available release version both in nixpkgs (nix_unstable channel) as well as the package's upstream repository. Since there's no known fixed version available in nixpkgs nor upstream, `nix_secupdates` classifies the update as `fix_not_available`. Note: the fix might still be in-progress, but not yet available in nix_unstable. Also, if the vulnerability is fixed with a patch without updating the version number, vulnxscan might still flag the issue (i.e. the output table will include false positives).
- Package `libmicrohttpd` local version 0.9.71 is potentially vulnerable to CVE-2023-27371. Latest version in nix_unstable is 0.9.72. However, that version is also vulnerable to CVE-2023-27371. Version 0.9.76, which is currently available in upstream, is not vulnerable. Therefore, `nix_secupdates` classifies the update as `fix_update_to_version_upstream` indicating `libmicrohttpd` should be updated to 0.9.76 which is currently available in upstream to mitigate the vulnerability.
- Package `libtiff` local version 4.5.0 is potentially vulnerable to CVE-2023-1916, however, `libtiff` is not available in repology so the latest nixpkgs version, as well as the upstream version are unknown. Therefore, `nix_secupdates` classifies the update as `err_missing_repology_version`.
- Package `openssl` local version 3.0.8 is potentially vulnerable to CVE-2023-0466. However, based on repology.org, `openssl` 3.0.8 is not vulnerable to CVE-2023-0466. Therefore, `nix_secupdates` is not able to determine the potential fixed version and sets the classification to `err_not_vulnerable_based_on_repology`.
