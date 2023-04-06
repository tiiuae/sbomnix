<!--
SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)

SPDX-License-Identifier: Apache-2.0
-->

# repology_cli

`repology_cli` is a command line interface to [repology.org](https://repology.org/). It supports querying package information via package search terms in the same manner as https://repology.org/projects/?search. In addition, it supports querying package information from all packages in a CycloneDX SBOM and printing out some simple statistics based on the input.


Table of Contents
=================

* [Getting Started](#getting-started)
   * [Running from Nix Development Shell](#running-from-nix-development-shell)
   * [Running as Python Script](#running-as-python-script)
* [Usage Examples](#usage-examples)
   * [Search by Package Name Exact Match](#search-by-package-name-exact-match)
   * [Search by Package Name Search Term](#search-by-package-name-search-term)
   * [Search by Package Names in SBOM](#search-by-package-names-in-sbom)
   * [Statistics: SBOM Packages](#statistics-sbom-packages)

## Getting Started

### Running as Nix Flake
`repology_cli` can be run as a [Nix flake](https://nixos.wiki/wiki/Flakes) from the `tiiuae/sbomnix` repository:
```bash
# '--' signifies the end of argument list for `nix`.
# '--help' is the first argument to `repology_cli`
$ nix run github:tiiuae/sbomnix#repology_cli -- --help
```

or from a local repository:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ nix run .#repology_cli -- --help
```

### Running from Nix Development Shell

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

From the development shell, you can run `repology_cli` as follows:
```bash
$ scripts/repology/repology_cli.py
```

### Running as Python Script
Running `repology_cli` as Python script requires Python packages specified in [requirements.txt](./requirements.txt). You can install the required packages with:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ pip install --user -r requirements.txt
```
After requirements have been installed, you can run repology_cli.py as follows:
```bash
$ source scripts/env.sh
$ scripts/repology/repology_cli.py 
```

## Usage Examples

### Search by Package Name Exact Match
Following query finds package name 'firefox' versions in 'nix_unstable' repository:
```bash
$ scripts/repology/repology_cli.py --pkg_exact "firefox" --repository nix_unstable

INFO     GET: https://repology.org/projects/?search=firefox&inrepo=nix_unstable
INFO     Repology package info, packages:5

| repo         | package | version               | status   | potentially_vulnerable | newest_upstream_release | repo_version_classify |
|--------------+---------+-----------------------+----------+------------------------+-------------------------+-----------------------|
| nix_unstable | firefox | 102-unwrapped-102.8.0 | legacy   |           1            | 110.0.1                 |                       |
| nix_unstable | firefox | 102.8.0               | legacy   |           1            | 110.0.1                 |                       |
| nix_unstable | firefox | 110.0.1               | newest   |           0            | 110.0.1                 |                       |
| nix_unstable | firefox | 111.0b7               | outdated |           0            | 110.0.1                 | repo_pkg_needs_update |
| nix_unstable | firefox | 111.0b8               | devel    |           0            | 110.0.1                 |                       |

For more details, see: https://repology.org/projects/?search=firefox&inrepo=nix_unstable

INFO     Wrote: repology_report.csv
```

Output table includes the datapoints available in repology.org, as stated by each column name. As an example, the first row in the above output table means:
- package information was fetched for repository 'nix_unstable'
- package name is 'firefox'
- latest 'nix_unstable' includes a version of firefox with version string '102-unwrapped-102.8.0'
- firefox '102-unwrapped-102.8.0' status is 'legacy'. The details of each classification status is available in https://repology.org/docs/about.
- firefox '102-unwrapped-102.8.0' is potentially vulnerable, meaning the package version is associated to at least one CVE. For details of which CVEs repology determined the package is associated to, see: https://repology.org/project/firefox/cves or https://repology.org/project/firefox/cves?version=102-unwrapped-102.8.0
- newest upstream release version of firefox known to repology is '110.0.1'

In addition to the above datapoints, `repology_cli` adds the column 'repo_version_classify', which simply states whether the specific package version appears updatable in the given repository. As an example, in the above output, the second last row states 'repo_pkg_needs_update' which means that it appears 'nix_unstable' should update the firefox '111.0b7' to the latest firefox upstream release version '110.0.1'.

Full list of repositories available in repology are available in https://repology.org/repositories/statistics. As an example, to repeat the earlier query for Debian 12, you would run:

```bash
$ scripts/repology/repology_cli.py --pkg_exact "firefox" --repository debian_12

INFO     GET: https://repology.org/projects/?search=firefox&inrepo=debian_12
INFO     Repology package info, packages:1

| repo      | package   | version   | status   |  potentially_vulnerable  | newest_upstream_release   | repo_version_classify   |
|-----------+-----------+-----------+----------+--------------------------+---------------------------+-------------------------|
| debian_12 | firefox   | 102.8.0   | outdated |            1             | 110.0.1                   | repo_pkg_needs_update   |

For more details, see: https://repology.org/projects/?search=firefox&inrepo=debian_12

INFO     Wrote: repology_report.csv
```

### Search by Package Name Search Term
Following query finds 'debian_12' packages that include 'firefox' anywhere in the name string:

```bash
$ scripts/repology/repology_cli.py --pkg_search "firefox" --repository debian_12

INFO     GET: https://repology.org/projects/?search=firefox&inrepo=debian_12
INFO     Repology package info, packages:5

| repo      | package                     | version | status   | potentially_vulnerable | newest_upstream_release | repo_version_classify |
|-----------+-----------------------------+---------+----------+------------------------+-------------------------+-----------------------|
| debian_12 | activity-aware-firefox      | 0.4.1   | unique   |           0            |                         |                       |
| debian_12 | firefox                     | 102.8.0 | outdated |           1            | 110.0.1                 | repo_pkg_needs_update |
| debian_12 | firefox-esr-mobile-config   | 3.2.0   | unique   |           0            |                         |                       |
| debian_12 | foxyproxy-firefox-extension | 7.5.1   | unique   |           0            |                         |                       |
| debian_12 | perl:firefox-marionette     | 1.35    | newest   |           0            | 1.35                    |                       |
```

Notice: using short search strings with `--pkg_search` might result a large number of matches and, thus, potentially a large number of queries to repology.org. To avoid spamming repology.org with such queries, `repology_cli` limits the number of requests sent to repology.org to at most one request per second. In addition, it caches all responses locally for 3600 seconds.

### Search by Package Names in SBOM
Following query finds 'nix_unstable' packages that match the packages in the CycloneDX sbom 'wget.runtime.sbom.cdx.json':

```bash
$ scripts/repology/repology_cli.py --sbom_cdx  wget.runtime.sbom.cdx.json --repository nix_unstable

INFO     GET: https://repology.org/projects/?search=glibc&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=libidn2&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=libunistring&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=openssl&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=pcre&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=util-linux-minimal&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=wget&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=zlib&inrepo=nix_unstable
INFO     Repology package info, packages:9

| repo         | package      | version  | status   | potentially_vulnerable | newest_upstream_release | version_sbom | sbom_version_classify | repo_version_classify |
|--------------+--------------+----------+----------+------------------------+-------------------------+--------------+-----------------------+-----------------------|
| nix_unstable | glibc        | 2.35-224 | outdated |           0            | 2.37                    | 2.35-224     | sbom_pkg_needs_update | repo_pkg_needs_update |
| nix_unstable | libidn2      | 2.3.2    | outdated |           0            | 2.3.4                   | 2.3.2        | sbom_pkg_needs_update | repo_pkg_needs_update |
| nix_unstable | libunistring | 1.0      | outdated |           0            | 1.1                     | 1.0          | sbom_pkg_needs_update | repo_pkg_needs_update |
| nix_unstable | openssl      | 1.1.1t   | legacy   |           0            | 3.0.8                   | 3.0.8        |                       |                       |
| nix_unstable | openssl      | 3.0.8    | newest   |           0            | 3.0.8                   | 3.0.8        |                       |                       |
| nix_unstable | pcre         | 8.45     | newest   |           0            | 8.45                    | 8.45         |                       |                       |
| nix_unstable | wget         | 1.21.3   | legacy   |           0            | 2.0.1                   | 1.21.3       |                       |                       |
| nix_unstable | wget         | 2.0.1    | newest   |           0            | 2.0.1                   | 1.21.3       | sbom_pkg_needs_update |                       |
| nix_unstable | zlib         | 1.2.13   | newest   |           0            | 1.2.13                  | 1.2.13       |                       |                       |
```

Output includes package details from the packages in the given SBOM that were also found in repology.org. In addition to the datapoints covered in section [Search by Package Name Exact Match](#search-by-package-name-exact-match), `repology_cli` adds the column 'sbom_version_classify' which states whether the package version in SBOM appears outdated. As an example, in the above output, package 'wget' version in sbom is '1.21.3'. Column 'sbom_version_classify' states 'sbom_pkg_needs_update' because 'nix_unstable' would have an update to the 'wget' package to version '2.0.1'.

### Statistics: SBOM Packages
Following is the same query as above, but adds the command-line argument `--stats` to print out some simple statistics that might help explain the results.

```bash
$ scripts/repology/repology_cli.py --sbom_cdx  wget.runtime.sbom.cdx.json --repository nix_unstable --stats
INFO     GET: https://repology.org/projects/?search=glibc&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=libidn2&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=libunistring&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=openssl&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=pcre&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=util-linux-minimal&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=wget&inrepo=nix_unstable
INFO     GET: https://repology.org/projects/?search=zlib&inrepo=nix_unstable
INFO     Repology package info, packages:9

| repo         | package      | version   | status   |  potentially_vulnerable  | newest_upstream_release   | version_sbom   | sbom_version_classify   | repo_version_classify   |
|--------------+--------------+-----------+----------+--------------------------+---------------------------+----------------+-------------------------+-------------------------|
| nix_unstable | glibc        | 2.35-224  | outdated |            0             | 2.37                      | 2.35-224       | sbom_pkg_needs_update   | repo_pkg_needs_update   |
| nix_unstable | libidn2      | 2.3.2     | outdated |            0             | 2.3.4                     | 2.3.2          | sbom_pkg_needs_update   | repo_pkg_needs_update   |
| nix_unstable | libunistring | 1.0       | outdated |            0             | 1.1                       | 1.0            | sbom_pkg_needs_update   | repo_pkg_needs_update   |
| nix_unstable | openssl      | 1.1.1t    | legacy   |            0             | 3.0.8                     | 3.0.8          |                         |                         |
| nix_unstable | openssl      | 3.0.8     | newest   |            0             | 3.0.8                     | 3.0.8          |                         |                         |
| nix_unstable | pcre         | 8.45      | newest   |            0             | 8.45                      | 8.45           |                         |                         |
| nix_unstable | wget         | 1.21.3    | legacy   |            0             | 2.0.1                     | 1.21.3         |                         |                         |
| nix_unstable | wget         | 2.0.1     | newest   |            0             | 2.0.1                     | 1.21.3         | sbom_pkg_needs_update   |                         |
| nix_unstable | zlib         | 1.2.13    | newest   |            0             | 1.2.13                    | 1.2.13         |                         |                         |

For more details, see: https://repology.org/projects/

INFO     
	Repology package statistics:
	 (see the status descriptions in: https://repology.org/docs/about)
	   Unique compared packages: 7 (100%)	(status in: ['newest', 'devel', 'unique', 'outdated'])
	    ==> newest: 4 (57%)
	    ==> outdated: 3 (43%)
	    ==> devel or unique: 0 (0%)
	    ==> potentially vulnerable: 0 (0%)

INFO     
	Repology SBOM package statistics:
	  Unique packages: 10 (100%)
	   ==> sbom packages in repology: 9 (90%)
	   ==> sbom packages not in repology: 1 (10%)
	        - IGNORED (sbom component is not a package in repology): 0
	        - NO_VERSION (sbom component is missing the version number): 0
	        - NOT_FOUND (sbom component was not found in repology): 1

INFO     Wrote: repology_report.csv
```
Section 'Repology package statistics' in the console output indicates that:
- There were seven packages whose status was one of `['newest', 'devel', 'unique', 'outdated']`. These are the package statuses `repology_cli` considers in the statistics output.
- Four out of the total of seven packages had the status 'newest'. This number indicates how many packages are up-to-date with its known latest release version in upstream.
- Three out of seven packages have the status 'outdated'. This number indicates how many packages are not up-to-date with its known latest upstream release version in 'nix_unstable' repository.
- There were no devel or unique packages. 'devel' packages indicate latest development or unstable package versions, whereas, 'unique' packages are only present in a single repository family, meaning there are no other sources for repology.org to compare them against.
- There were no packages with known vulnerabilities associated to them.

Section 'Repology SBOM package statistics' in the console output indicates that:
- The baseline for SBOM package comparison is ten unique packages. This number includes the unique components in the cdx SBOM (as identified by the component name and version), as well as other current package versions in 'nix_unstable' known to repology.
- Nine component names in the SBOM can be matched with package names in repology.
- One package was not included to the comparison by `repology_cli`. The reason is 'NOT_FOUND', meaning the package was not found in repology.org. Other possible reasons for `repology_cli` to skip SBOM packages are IGNORED and NO_VERSION. IGNORED means the sbom component name indicates the component is not a package in repology.org. Typical examples of IGNORED packages would be archives (.tar.gz) or patches (.patch). NO_VERSION means the sbom component was missing the version information. Typically, such packages are service files, scripts, or configuration files that are not considered as packages in repology.org but can be included as separate components in the SBOM.

In addition to the console output `repology_cli` outputs the full data set in csv file. As an example, you could query the `repology_report.csv` for more details of the skipped packages:

```bash

$ csvsql --query "select * from repology_report where status == 'NOT_FOUND'" repology_report.csv | csvlook

| repo         | package            | version | status    |       | version_sbom |
| ------------ | ------------------ | ------- | --------- |  ...  | ------------ |
| nix_unstable | util-linux-minimal | 2.38.1  | NOT_FOUND |       | 2.38.1       |
```

Above, we can see the package 'util-linux-minimal' which is one of the components in the example sbom 'wget.runtime.sbom.cdx.json', is not available (with that exact same name) in repology.org.
