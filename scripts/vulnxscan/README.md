<!--
SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)

SPDX-License-Identifier: Apache-2.0
-->

# vulnxscan

`vulnxscan` is a command line utility that demonstrates automating vulnerability scans using SBOM as input. It mainly targets nix packages, however, it can be used with any other targets too as long as the target is expressed as valid CycloneDX SBOM.

Table of Contents
=================
* [Getting Started](#getting-started)
* [Usage Examples](#usage-examples)
* [Supported Scanners](#supported-scanners)
   * [Nix and OSV Vulnerability Database](#nix-and-osv-vulnerability-database)
   * [Nix and Grype](#nix-and-grype)
   * [Vulnix](#vulnix)
* [Vulnxscan Usage Examples](#vulnxscan-usage-examples)
   * [Running Vulnxscan as Flake](#running-vulnxscan-as-flake)
   * [Find Vulnerabilities Impacting Runtime Dependencies](#find-vulnerabilities-impacting-runtime-dependencies)
   * [Find Vulnerabilities Given SBOM as Input](#find-vulnerabilities-given-sbom-as-input)
   * [Find Vulnerabilities Impacting Vuildtime and Runtime Dependencies](#find-vulnerabilities-impacting-vuildtime-and-runtime-dependencies)
* [Footnotes and Future Work](#footnotes-and-future-work)

## Getting Started
To get started, follow the [Getting Started](../../README.md#getting-started) section from the main [README](../../README.md).

## Usage Examples
In the below examples, we use `sbomnix` itself as an example target for `vulnxscan`.
To get the target out-path, build `sbomnix` with `nix-build`:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ nix-build
```
Which creates a `result` symlink that points to `sbomnix` out-path on your local system:
```bash
$ ls -l result
lrwxrwxrwx   result -> /nix/store/6y93c1b4453mjqn6ar6sszcf06svr3jl-python3.10-sbomnix-1.2.0
```

## Supported Scanners
### Nix and OSV Vulnerability Database
[OSV](https://osv.dev/) is a vulnerability database for open-source projects [initiated by Google](https://security.googleblog.com/2021/02/launching-osv-better-vulnerability.html). 

[OSV database](https://osv.dev/list?ecosystem=) currently [does not support Nix ecosystem](https://ossf.github.io/osv-schema/#affectedpackage-field), so queries that specify Nix as ecosystem would not return any matches. For this reason `vulnxscan` currently does not use Google's official [OSV-Scanner](https://security.googleblog.com/2022/12/announcing-osv-scanner-vulnerability.html) front-end, but implements it's own OSV client demo in [osv.py](./osv.py).

`osv.py` sends queries to [OSV API](https://osv.dev/docs/) without specifying the ecosystem, only the target package name and version. At the time of writing, such queries to OSV API return vulnerabilities that match the given package and version across all ecosystems. As a result, the OSV vulnerabilities for Nix ecosystem will include false positives. 

Also, it is worth mentioning that OSV queries without ecosystem are undocumented in the [API specification](https://osv.dev/docs/#tag/api/operation/OSV_QueryAffected) currently.

### Nix and Grype
[Grype](https://github.com/anchore/grype) is a vulnerability scanner targeted for container images. It uses the vulnerability data from [variety of publicly available data sources](https://github.com/anchore/grype#grypes-database). Grype also [supports input from CycloneDX SBOM](https://github.com/anchore/grype#supported-sources) which makes it possible to use Grype with SBOM input from `sbomnix`, thus, allowing Grype scans against Nix targets.

### Vulnix
[Vulnix](https://github.com/flyingcircusio/vulnix) is a vulnerability scanner intended for Nix targets. It uses [NIST NVD](https://nvd.nist.gov/vuln) vulnerability database.

Vulnix matches vulnerabilities based on [heuristic](https://github.com/flyingcircusio/vulnix/blob/f56f3ac857626171b95e51d98cb6874278f789d3/src/vulnix/derivation.py#L104), which might result more false positives compared to direct match. False positives due to rough heuristic are an [intended feature](https://github.com/flyingcircusio/vulnix#whitelisting) in Vulnix. On the other hand, Vulnix accounts [CVE patches](https://github.com/flyingcircusio/vulnix#cve-patch-auto-detection) applied on Nix packages when matching vulnerabilities, something currently not supported by other scanners.

## Vulnxscan Usage Examples

### Running Vulnxscan as Flake
`vulnxscan` can be run as a [Nix flake](https://nixos.wiki/wiki/Flakes) from the `tiiuae/sbomnix` repository:
```bash
# '--' signifies the end of argument list for `nix`.
# '--help' is the first argument to `vulnxscan`
$ nix run github:tiiuae/sbomnix#vulnxscan -- --help
```

or from a local repository:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ nix run .#vulnxscan -- --help
```

### Find Vulnerabilities Impacting Runtime Dependencies
This example shows how to use `vulnxscan` to summarize vulnerabilities impacting the given target or any of its runtime dependencies.

```bash
# Alternatively, run with flakes: 'nix run .#vulnxscan -- ./result'
$ vulnxscan ./result

INFO     Generating SBOM for target '/nix/store/8pvrr84a3aw12bvi45hl7wx01a8iqgni-python3.10-sbomnix-1.2.0'
INFO     Loading runtime dependencies referenced by '/nix/store/8pvrr84a3aw12bvi45hl7wx01a8iqgni-python3.10-sbomnix-1.2.0'
INFO     Using SBOM '/tmp/nix-shell.PCbbzS/vulnxscan_lu4w8hac.json'
INFO     Running vulnix scan
INFO     Running grype scan
INFO     Running OSV scan
INFO     Querying vulnerabilities
INFO     Console report

Potential vulnerabilities impacting 'result' or some of its runtime dependencies:

| vuln_id             | url                                             | package    | version| grype | osv |vulnix| sum |
|---------------------+-------------------------------------------------+------------+--------+-------+-----+------+-----|
| GHSA-r9hx-vwmv-q579 | https://osv.dev/GHSA-r9hx-vwmv-q579             | setuptools | 65.3.0 |   0   |  1  |  0   |  1  |
| GHSA-qwmp-2cf2-g9g6 | https://osv.dev/GHSA-qwmp-2cf2-g9g6             | wheel      | 0.37.1 |   0   |  1  |  0   |  1  |
| CVE-2022-48281      | https://nvd.nist.gov/vuln/detail/CVE-2022-48281 | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-46908      | https://nvd.nist.gov/vuln/detail/CVE-2022-46908 | sqlite     | 3.39.4 |   1   |  0  |  0   |  1  |
| CVE-2022-40897      | https://nvd.nist.gov/vuln/detail/CVE-2022-40897 | setuptools | 65.3.0 |   1   |  0  |  0   |  1  |
| CVE-2022-34526      | https://nvd.nist.gov/vuln/detail/CVE-2022-34526 | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-34000      | https://nvd.nist.gov/vuln/detail/CVE-2022-34000 | libjxl     | 0.6.1  |   1   |  0  |  0   |  1  |
| CVE-2022-28506      | https://nvd.nist.gov/vuln/detail/CVE-2022-28506 | giflib     | 5.2.1  |   1   |  1  |  0   |  2  |
| CVE-2022-3996       | https://nvd.nist.gov/vuln/detail/CVE-2022-3996  | openssl    | 3.0.7  |   1   |  0  |  0   |  1  |
| CVE-2022-3970       | https://nvd.nist.gov/vuln/detail/CVE-2022-3970  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-3627       | https://nvd.nist.gov/vuln/detail/CVE-2022-3627  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-3626       | https://nvd.nist.gov/vuln/detail/CVE-2022-3626  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-3599       | https://nvd.nist.gov/vuln/detail/CVE-2022-3599  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-3598       | https://nvd.nist.gov/vuln/detail/CVE-2022-3598  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-3597       | https://nvd.nist.gov/vuln/detail/CVE-2022-3597  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-3570       | https://nvd.nist.gov/vuln/detail/CVE-2022-3570  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-2953       | https://nvd.nist.gov/vuln/detail/CVE-2022-2953  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-2521       | https://nvd.nist.gov/vuln/detail/CVE-2022-2521  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-2520       | https://nvd.nist.gov/vuln/detail/CVE-2022-2520  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-2519       | https://nvd.nist.gov/vuln/detail/CVE-2022-2519  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-2058       | https://nvd.nist.gov/vuln/detail/CVE-2022-2058  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-2057       | https://nvd.nist.gov/vuln/detail/CVE-2022-2057  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2022-2056       | https://nvd.nist.gov/vuln/detail/CVE-2022-2056  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| OSV-2022-674        | https://osv.dev/OSV-2022-674                    | dav1d      | 1.0.0  |   0   |  1  |  0   |  1  |
| CVE-2021-26945      | https://nvd.nist.gov/vuln/detail/CVE-2021-26945 | openexr    | 2.5.8  |   1   |  0  |  0   |  1  |
| CVE-2021-26260      | https://nvd.nist.gov/vuln/detail/CVE-2021-26260 | openexr    | 2.5.8  |   1   |  0  |  0   |  1  |
| CVE-2021-23215      | https://nvd.nist.gov/vuln/detail/CVE-2021-23215 | openexr    | 2.5.8  |   1   |  0  |  0   |  1  |
| CVE-2021-23169      | https://nvd.nist.gov/vuln/detail/CVE-2021-23169 | openexr    | 2.5.8  |   1   |  0  |  0   |  1  |
| CVE-2021-4048       | https://nvd.nist.gov/vuln/detail/CVE-2021-4048  | lapack     | 3      |   1   |  0  |  1   |  2  |
| CVE-2021-3933       | https://nvd.nist.gov/vuln/detail/CVE-2021-3933  | openexr    | 2.5.8  |   1   |  0  |  0   |  1  |
| CVE-2021-3605       | https://nvd.nist.gov/vuln/detail/CVE-2021-3605  | openexr    | 2.5.8  |   1   |  0  |  0   |  1  |
| CVE-2021-3598       | https://nvd.nist.gov/vuln/detail/CVE-2021-3598  | openexr    | 2.5.8  |   1   |  0  |  0   |  1  |
| CVE-2020-18032      | https://nvd.nist.gov/vuln/detail/CVE-2020-18032 | graphviz   | 0.20.1 |   1   |  0  |  0   |  1  |
| OSV-2020-1610       | https://osv.dev/OSV-2020-1610                   | openexr    | 2.5.8  |   0   |  1  |  0   |  1  |
| CVE-2017-5436       | https://nvd.nist.gov/vuln/detail/CVE-2017-5436  | graphite2  | 1.3.14 |   1   |  0  |  0   |  1  |
| CVE-2016-2781       | https://nvd.nist.gov/vuln/detail/CVE-2016-2781  | coreutils  | 9.1    |   1   |  0  |  0   |  1  |
| CVE-2015-7313       | https://nvd.nist.gov/vuln/detail/CVE-2015-7313  | libtiff    | 4.4.0  |   1   |  0  |  0   |  1  |
| CVE-2014-9157       | https://nvd.nist.gov/vuln/detail/CVE-2014-9157  | graphviz   | 7.0.0  |   1   |  0  |  0   |  1  |
| CVE-2014-9157       | https://nvd.nist.gov/vuln/detail/CVE-2014-9157  | graphviz   | 0.20.1 |   1   |  0  |  0   |  1  |
| CVE-2008-4555       | https://nvd.nist.gov/vuln/detail/CVE-2008-4555  | graphviz   | 0.20.1 |   1   |  0  |  0   |  1  |
| CVE-2005-4803       | https://nvd.nist.gov/vuln/detail/CVE-2005-4803  | graphviz   | 0.20.1 |   1   |  0  |  0   |  1  |

INFO     Wrote: vulns.csv
```

As printed in the console output, `vulnxscan` first creates an SBOM, then feeds the SBOM (or target path) as input to different vulnerability scanners: [vulnix](https://github.com/flyingcircusio/vulnix) (for reference), [grype](https://github.com/anchore/grype), and [osv.py](https://github.com/tiiuae/sbomnix/blob/main/scripts/vulnxscan/osv.py) and creates a summary report. The summary report lists the newest vulnerabilities on top, with the `sum` column indicating how many scanners agreed with the exact same finding. In addition to the console output, `vulnxscan` writes the report to csv-file to allow easier post-processing of the output.

### Find Vulnerabilities Given SBOM as Input
This example shows how to use `vulnxscan` to summarize vulnerabilities impacting components in the given CycloneDX SBOM.

First, we use `sbomnix` to generate SBOM for the example target:
```bash
# Alternatively, run with flakes: 'nix run .#sbomnix -- ./result'
$ sbomnix ./result
..
INFO     Wrote: sbom.cdx.json
```

Then, give the generated SBOM as input to `vulnxscan`:
```bash
# Alternatively, run with flakes: 'nix run .#vulnxscan -- --sbom sbom.cdx.json'
$ vulnxscan --sbom sbom.cdx.json
INFO     Running grype scan
INFO     Running OSV scan
INFO     Querying vulnerabilities
INFO     Console report

Potential vulnerabilities impacting components in 'sbom.cdx.json':

| vuln_id             | url                                             |  package    |  version   | grype | osv |  sum  |
|---------------------+-------------------------------------------------+-------------+------------+-------+-----+-------|
| GHSA-r9hx-vwmv-q579 | https://osv.dev/GHSA-r9hx-vwmv-q579             |  setuptools |  65.3.0    |   0   |  1  |   1   |
| GHSA-qwmp-2cf2-g9g6 | https://osv.dev/GHSA-qwmp-2cf2-g9g6             |  wheel      |  0.37.1    |   0   |  1  |   1   |
| CVE-2022-48281      | https://nvd.nist.gov/vuln/detail/CVE-2022-48281 |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-46908      | https://nvd.nist.gov/vuln/detail/CVE-2022-46908 |  sqlite     |  3.39.4    |   1   |  0  |   1   |
| CVE-2022-40897      | https://nvd.nist.gov/vuln/detail/CVE-2022-40897 |  setuptools |  65.3.0    |   1   |  0  |   1   |
| CVE-2022-34526      | https://nvd.nist.gov/vuln/detail/CVE-2022-34526 |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-34000      | https://nvd.nist.gov/vuln/detail/CVE-2022-34000 |  libjxl     |  0.6.1     |   1   |  0  |   1   |
| CVE-2022-28506      | https://nvd.nist.gov/vuln/detail/CVE-2022-28506 |  giflib     |  5.2.1     |   1   |  1  |   2   |
| CVE-2022-3996       | https://nvd.nist.gov/vuln/detail/CVE-2022-3996  |  openssl    |  3.0.7     |   1   |  0  |   1   |
| CVE-2022-3970       | https://nvd.nist.gov/vuln/detail/CVE-2022-3970  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-3627       | https://nvd.nist.gov/vuln/detail/CVE-2022-3627  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-3626       | https://nvd.nist.gov/vuln/detail/CVE-2022-3626  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-3599       | https://nvd.nist.gov/vuln/detail/CVE-2022-3599  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-3598       | https://nvd.nist.gov/vuln/detail/CVE-2022-3598  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-3597       | https://nvd.nist.gov/vuln/detail/CVE-2022-3597  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-3570       | https://nvd.nist.gov/vuln/detail/CVE-2022-3570  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-2953       | https://nvd.nist.gov/vuln/detail/CVE-2022-2953  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-2521       | https://nvd.nist.gov/vuln/detail/CVE-2022-2521  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-2520       | https://nvd.nist.gov/vuln/detail/CVE-2022-2520  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-2519       | https://nvd.nist.gov/vuln/detail/CVE-2022-2519  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-2058       | https://nvd.nist.gov/vuln/detail/CVE-2022-2058  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-2057       | https://nvd.nist.gov/vuln/detail/CVE-2022-2057  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2022-2056       | https://nvd.nist.gov/vuln/detail/CVE-2022-2056  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| OSV-2022-674        | https://osv.dev/OSV-2022-674                    |  dav1d      |  1.0.0     |   0   |  1  |   1   |
| CVE-2021-26945      | https://nvd.nist.gov/vuln/detail/CVE-2021-26945 |  openexr    |  2.5.8     |   1   |  0  |   1   |
| CVE-2021-26260      | https://nvd.nist.gov/vuln/detail/CVE-2021-26260 |  openexr    |  2.5.8     |   1   |  0  |   1   |
| CVE-2021-23215      | https://nvd.nist.gov/vuln/detail/CVE-2021-23215 |  openexr    |  2.5.8     |   1   |  0  |   1   |
| CVE-2021-23169      | https://nvd.nist.gov/vuln/detail/CVE-2021-23169 |  openexr    |  2.5.8     |   1   |  0  |   1   |
| CVE-2021-4048       | https://nvd.nist.gov/vuln/detail/CVE-2021-4048  |  lapack     |  3         |   1   |  0  |   1   |
| CVE-2021-3933       | https://nvd.nist.gov/vuln/detail/CVE-2021-3933  |  openexr    |  2.5.8     |   1   |  0  |   1   |
| CVE-2021-3605       | https://nvd.nist.gov/vuln/detail/CVE-2021-3605  |  openexr    |  2.5.8     |   1   |  0  |   1   |
| CVE-2021-3598       | https://nvd.nist.gov/vuln/detail/CVE-2021-3598  |  openexr    |  2.5.8     |   1   |  0  |   1   |
| CVE-2020-18032      | https://nvd.nist.gov/vuln/detail/CVE-2020-18032 |  graphviz   |  0.20.1    |   1   |  0  |   1   |
| OSV-2020-1610       | https://osv.dev/OSV-2020-1610                   |  openexr    |  2.5.8     |   0   |  1  |   1   |
| CVE-2017-5436       | https://nvd.nist.gov/vuln/detail/CVE-2017-5436  |  graphite2  |  1.3.14    |   1   |  0  |   1   |
| CVE-2016-2781       | https://nvd.nist.gov/vuln/detail/CVE-2016-2781  |  coreutils  |  9.1       |   1   |  0  |   1   |
| CVE-2015-7313       | https://nvd.nist.gov/vuln/detail/CVE-2015-7313  |  libtiff    |  4.4.0     |   1   |  0  |   1   |
| CVE-2014-9157       | https://nvd.nist.gov/vuln/detail/CVE-2014-9157  |  graphviz   |  7.0.0     |   1   |  0  |   1   |
| CVE-2014-9157       | https://nvd.nist.gov/vuln/detail/CVE-2014-9157  |  graphviz   |  0.20.1    |   1   |  0  |   1   |
| CVE-2008-4555       | https://nvd.nist.gov/vuln/detail/CVE-2008-4555  |  graphviz   |  0.20.1    |   1   |  0  |   1   |
| CVE-2005-4803       | https://nvd.nist.gov/vuln/detail/CVE-2005-4803  |  graphviz   |  0.20.1    |   1   |  0  |   1   |

INFO     Wrote: vulns.csv
```
Notice that `vulnxscan` drops the Vulnix scan when the input is SBOM. This is due to the Vulnix not supporting SBOM input at the time of writing.


### Find Vulnerabilities Impacting Vuildtime and Runtime Dependencies
By default, `vulnxscan` scans the given target for vulnerabilities that impact its runtime-only dependencies. This example shows how to use `vulnxscan` to include also buildtime dependencies to the scan.

```bash
# Alternatively, run with flakes: 'nix run .#vulnxscan -- ./result --buildtime'
$ vulnxscan ./result --buildtime
# ... output not included in this snippet ... 
```

## Footnotes and Future Work

For now, consider `vulnxscan` as a demonstration. The list of reported vulnerabilities includes false positives for various reasons:
 - `sbomnix` currently does not include the information about applied patches to the CycloneDX SBOM. `sbomnix` collects the list of patches applied on top of each package and outputs the collected data in its csv output, but it does not add the information to the cdx SBOM. CycloneDX apparently would support such information via the [pedigree](https://cyclonedx.org/use-cases/#pedigree) attribute.
 - Vulnerability scanners lack support for parsing the patch data: even if `sbomnix` added the patch data to the output SBOM, we suspect not many vulnerability scanners would read the information. As an example, the following discussion touches this topic on DependencyTrack: https://github.com/DependencyTrack/dependency-track/issues/919.
 - Identifying packages is hard as pointed out in https://discourse.nixos.org/t/the-future-of-the-vulnerability-roundups/22424/5. As an example, CPEs are inaccurate which causes issues in matching vulnerabilities: https://github.com/DependencyTrack/dependency-track/discussions/2290.
 - Nix ecosystem is not supported in OSV: the way `osv.py` makes use of OSV data for Nix targets -- as explained in section [Nix and OSV vulnerability database](#nix-and-osv-vulnerability-database) -- makes the reported OSV vulnerabilities include false positives.

##### Other Future Work
- [vulnxscan](./vulnxscan.py) still lives under [scripts](../../scripts/) directory since the way it invokes grype and vulnix is not very Nix-like, and should be done properly. 
- [vulnxscan](./vulnxscan.py) uses vulnix from a [forked repository](https://github.com/henrirosten/vulnix), to include Vulnix [support for scanning runtime-only dependencies](https://github.com/flyingcircusio/vulnix/compare/master...henrirosten:vulnix:master).
- [vulnxscan](./vulnxscan.py) could include more scanners in addition to [vulnix](https://github.com/flyingcircusio/vulnix), [grype](https://github.com/anchore/grype), and [osv.py](https://github.com/tiiuae/sbomnix/blob/main/scripts/vulnxscan/osv.py). Suggestions for other open-source scanners, especially those that can digest CycloneDX SBOM are welcome.

