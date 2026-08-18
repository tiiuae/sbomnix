<!--
SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# vulnxscan

[`vulnxscan`](../src/vulnxscan/vulnxscan_cli.py) is a command line utility that demonstrates running vulnerability scans using SBOM as input. It mainly targets nix packages, however, it can be used with any other targets too as long as the target is expressed as valid CycloneDX SBOM.

Table of Contents
=================
* [Getting Started](#getting-started)
* [Example Target](#example-target)
* [Supported Scanners](#supported-scanners)
   * [Nix and OSV Vulnerability Database](#nix-and-osv-vulnerability-database)
   * [Nix and Grype](#nix-and-grype)
   * [Vulnix](#vulnix)
* [Vulnxscan Usage Examples](#vulnxscan-usage-examples)
   * [Find Vulnerabilities Impacting Runtime Dependencies](#find-vulnerabilities-impacting-runtime-dependencies)
   * [Whitelisting Vulnerabilities](#whitelisting-vulnerabilities)
   * [Find Vulnerabilities Given SBOM as Input](#find-vulnerabilities-given-sbom-as-input)
   * [Find Vulnerabilities Impacting Buildtime and Runtime Dependencies](#find-vulnerabilities-impacting-buildtime-and-runtime-dependencies)
   * [Using Whitelist to Record Manual Analysis Results](#using-whitelist-to-record-manual-analysis-results)
   * [Triage to Help Manual Analysis](#triage-to-help-manual-analysis)
   * [Component Patch Evidence](#component-patch-evidence)
* [Footnotes and Future Work](#footnotes-and-future-work)

## Getting Started
To get started, follow the [Getting Started](../README.md#getting-started) section from the main [README](../README.md).

As an example, to run the `vulnxscan` from your local clone of the `tiiuae/sbomnix` repository:
```bash
# '--' signifies the end of argument list for `nix`.
# '--help' is the first argument to `vulnxscan`
$ nix run .#vulnxscan -- --help
```

## Example Target
In the below examples, we use `git` as an example target for `vulnxscan`, referred to by flakeref `github:NixOS/nixpkgs/nixos-unstable#git`.

## Supported Scanners
### Nix and OSV Vulnerability Database
[OSV](https://osv.dev/) is a vulnerability database for open-source projects [initiated by Google](https://security.googleblog.com/2021/02/launching-osv-better-vulnerability.html).

[OSV database](https://osv.dev/list?ecosystem=) currently [does not support Nix ecosystem](https://ossf.github.io/osv-schema/#affectedpackage-field), so queries that specify Nix as ecosystem would not return any matches. For this reason `vulnxscan` currently does not use Google's official [OSV-Scanner](https://security.googleblog.com/2022/12/announcing-osv-scanner-vulnerability.html) front-end, but implements its own OSV client demo in [osv.py](../src/vulnxscan/osv.py).

`osv.py` sends queries to [OSV API](https://osv.dev/docs/) without specifying the ecosystem, only the target package name and version. At the time of writing, such queries to OSV API return vulnerabilities that match the given package and version across all ecosystems. As a result, the OSV vulnerabilities for Nix ecosystem will include false positives.

Also, it is worth mentioning that OSV queries without ecosystem are undocumented in the [API specification](https://osv.dev/docs/#tag/api/operation/OSV_QueryAffected) currently.

### Nix and Grype
[Grype](https://github.com/anchore/grype) is a vulnerability scanner targeted for container images. It uses the vulnerability data from [a variety of publicly available data sources](https://github.com/anchore/grype#grypes-database). Grype also [supports input from CycloneDX SBOM](https://github.com/anchore/grype#supported-sources) which makes it possible to use Grype with SBOM input from `sbomnix`, thus, allowing Grype scans against Nix targets.

When the CPE dictionary cannot be loaded, `sbomnix` and `vulnxscan` warn and fall back to less accurate CPE identifiers. Pass `--require-cpe-dictionary` to either command to fail instead when generating an SBOM for vulnerability scanning. This option has no effect when `vulnxscan --sbom` uses an existing SBOM.

### Vulnix
[Vulnix](https://github.com/nix-community/vulnix) is a vulnerability scanner intended for Nix targets. It uses [NIST NVD](https://nvd.nist.gov/vuln) vulnerability database.

Vulnix matches vulnerabilities based on [heuristic](https://github.com/nix-community/vulnix/blob/f56f3ac857626171b95e51d98cb6874278f789d3/src/vulnix/derivation.py#L104), which might result more false positives compared to direct match. False positives due to rough heuristic are an [intended feature](https://github.com/nix-community/vulnix#whitelisting) in vulnix. On the other hand, vulnix accounts [CVE patches](https://github.com/nix-community/vulnix#cve-patch-auto-detection) applied on Nix packages when matching vulnerabilities, something currently not directly supported by other scanners.

## Vulnxscan Usage Examples

### Find Vulnerabilities Impacting Runtime Dependencies
This example shows how to use `vulnxscan` to summarize vulnerabilities impacting the given target or any of its runtime dependencies. The captured output is illustrative; exact versions and findings will differ depending on the package versions resolved at run time.

```bash
# Target can be specified as a flakeref or a nix store path, e.g.:
# vulnxscan .
# vulnxscan github:tiiuae/sbomnix
# vulnxscan nixpkgs#git
# vulnxscan /nix/store/...
# Ref: https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-flake.html#flake-references
$ vulnxscan github:NixOS/nixpkgs/nixos-unstable#git

INFO     Generating SBOM for target '/nix/store/...-git-<version>'
INFO     CVE-2023-2975 for 'openssl' is patched with: ['/nix/store/7gz0nj14469r9dlh8p0j5w5wjj3b6hw4-CVE-2023-2975.patch']
INFO     CVE-2023-2975 for 'openssl' is patched with: ['/nix/store/7gz0nj14469r9dlh8p0j5w5wjj3b6hw4-CVE-2023-2975.patch']
INFO     Console report

Potential vulnerabilities impacting version_local:

| vuln_id          | url                                               | package   | version | severity | grype | osv | vulnix | sum |
|------------------+---------------------------------------------------+-----------+---------+----------+-------+-----+--------+-----|
| CVE-2023-3817    | https://nvd.nist.gov/vuln/detail/CVE-2023-3817    | openssl   | 3.0.9   | 5.3      |   1   |  0  |   1    |  2  |
| CVE-2022-38663   | https://nvd.nist.gov/vuln/detail/CVE-2022-38663   | git       | 2.41.0  | 6.5      |   0   |  0  |   1    |  1  |
| CVE-2022-36884   | https://nvd.nist.gov/vuln/detail/CVE-2022-36884   | git       | 2.41.0  | 5.3      |   0   |  0  |   1    |  1  |
| CVE-2022-36883   | https://nvd.nist.gov/vuln/detail/CVE-2022-36883   | git       | 2.41.0  | 7.5      |   0   |  0  |   1    |  1  |
| CVE-2022-36882   | https://nvd.nist.gov/vuln/detail/CVE-2022-36882   | git       | 2.41.0  | 8.8      |   0   |  0  |   1    |  1  |
| CVE-2022-30949   | https://nvd.nist.gov/vuln/detail/CVE-2022-30949   | git       | 2.41.0  | 5.3      |   0   |  0  |   1    |  1  |
| CVE-2022-30948   | https://nvd.nist.gov/vuln/detail/CVE-2022-30948   | git       | 2.41.0  | 7.5      |   0   |  0  |   1    |  1  |
| CVE-2022-30947   | https://nvd.nist.gov/vuln/detail/CVE-2022-30947   | git       | 2.41.0  | 7.5      |   0   |  0  |   1    |  1  |
| MAL-2022-4301    | https://osv.dev/MAL-2022-4301                     | libidn2   | 2.3.4   |          |   0   |  1  |   0    |  1  |
| CVE-2021-21684   | https://nvd.nist.gov/vuln/detail/CVE-2021-21684   | git       | 2.41.0  | 6.1      |   0   |  0  |   1    |  1  |
| CVE-2020-2136    | https://nvd.nist.gov/vuln/detail/CVE-2020-2136    | git       | 2.41.0  | 5.4      |   0   |  0  |   1    |  1  |
| CVE-2019-1003010 | https://nvd.nist.gov/vuln/detail/CVE-2019-1003010 | git       | 2.41.0  | 4.3      |   0   |  0  |   1    |  1  |
| CVE-2018-1000182 | https://nvd.nist.gov/vuln/detail/CVE-2018-1000182 | git       | 2.41.0  | 6.4      |   0   |  0  |   1    |  1  |
| CVE-2018-1000110 | https://nvd.nist.gov/vuln/detail/CVE-2018-1000110 | git       | 2.41.0  | 5.3      |   0   |  0  |   1    |  1  |
| CVE-2016-2781    | https://nvd.nist.gov/vuln/detail/CVE-2016-2781    | coreutils | 9.3     | 6.5      |   1   |  0  |   0    |  1  |

INFO     Wrote: vulns.csv
```

`vulnxscan` first creates an SBOM, then feeds the SBOM (or target path) as input to different vulnerability scanners: [vulnix](https://github.com/nix-community/vulnix), [grype](https://github.com/anchore/grype), and [osv.py](../src/vulnxscan/osv.py) and creates a summary report. The summary report lists the newest vulnerabilities on top, with the `sum` column indicating how many scanners agreed with the exact same finding. In addition to the console output, `vulnxscan` writes the report to csv-file `vulns.csv` to allow easier post-processing of the output.

It is worth mentioning that `vulnxscan` filters out vulnerabilities that it detects are patched, as printed out in the console output on lines like '`CVE-2023-2975 for 'openssl' is patched with: ['/nix/store/7gz0nj14469r9dlh8p0j5w5wjj3b6hw4-CVE-2023-2975.patch']`'.
This patch auto-detection works in the similar way as the [patch auto-detection on vulnix](https://github.com/nix-community/vulnix#cve-patch-auto-detection), that is, it is based on detecting vulnerability identifiers from the patch filenames.

A finding is filtered out only when *every* derivation it resolves to carries such a patch. When a closure contains several derivations with the same package name and version but different patch metadata, the finding stays in the report and its patch evidence is summarized in the output columns described in [Component Patch Evidence](#component-patch-evidence).


### Whitelisting Vulnerabilities
`vulnxscan` supports whitelisting vulnerabilities to exclude false positives, unfixable issues, or vulnerabilities known to be addressed. Whitelist is a csv file that contains rules for the vulnerabilities to be excluded from the vulnxscan console report. Consider the following example whitelist:

```
$ csvlook whitelist.csv

| vuln_id        | package   | version_local | version_local_regex | comment                                                                 |
| -------------- | --------- | ------------- | ------------------- | ----------------------------------------------------------------------- |
| MAL-2022-4301  |           |               |                     | Incorrect package: Issue refers npm libidn2, not libidn2.               |
| CVE-2016-2781  | coreutils | 9.5           |                     | NVD data issue: CPE entry does not correctly state the version numbers. |
| CVE-20.*       | git       |               |                     | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| CVE-2025-.*    | go        |               | .*-linux-amd64-bootstrap | Build-time bootstrap Go artifact.                                       |
```

`vuln_id` and `comment` are mandatory columns. Empty optional match
columns do not restrict the rule.

| column                | required | behavior                                                                                  |
| --------------------- | -------- | ----------------------------------------------------------------------------------------- |
| `vuln_id`             | yes      | Regular expression full match against the finding `vuln_id`.                              |
| `comment`             | yes      | Copied to the finding `whitelist_comment` field.                                          |
| `package`             | no       | Exact match against the finding `package` when non-empty.                                 |
| `version_local`       | no       | Exact match against the finding local version when non-empty.                             |
| `version_local_regex` | no       | Regular expression full match against the finding local version when non-empty.           |
| `whitelist`           | no       | Defaults to `True`; `False` or `0` annotates matching rows without suppressing them.      |

When both `version_local` and `version_local_regex` are set, both
filters must match.

In case many rules match a vulnerability, rules on top of the whitelist are given higher priority.

To be able to verify which vulnerabilities are whitelisted, `vulnxscan` csv output `vulns.csv` includes both whitelisted and non-whitelisted vulnerabilities implied with boolean column `whitelist`. `vulns.csv` also includes the `comment` section from the whitelist to be able to verify the reason for whitelisting each vulnerability. Below example shows applying the above example whitelist against the `git` vulnxscan output from the earlier example.

```bash
# Given the whitelist.csv contents:
$ cat whitelist.csv
"vuln_id","package","version_local","version_local_regex","comment"
"MAL-2022-4301",,,,"Incorrect package: Issue refers npm libidn2, not libidn2."
"CVE-2016-2781","coreutils","9.5",,"NVD data issue: CPE entry does not correctly state the version numbers."
"CVE-20.*","git",,,"Incorrect package: Impacts Jenkins git plugin, not git."
"CVE-2025-.*","go",,".*-linux-amd64-bootstrap","Build-time bootstrap Go artifact."

# Apply the whitelist to git vulnxscan output
$ vulnxscan github:NixOS/nixpkgs/nixos-unstable#git --whitelist=whitelist.csv

INFO     Generating SBOM for target '/nix/store/...-git-<version>'
INFO     CVE-2023-2975 for 'openssl' is patched with: ['/nix/store/7gz0nj14469r9dlh8p0j5w5wjj3b6hw4-CVE-2023-2975.patch']
INFO     CVE-2023-2975 for 'openssl' is patched with: ['/nix/store/7gz0nj14469r9dlh8p0j5w5wjj3b6hw4-CVE-2023-2975.patch']
INFO     Console report

Potential vulnerabilities impacting version_local:

# Note: the console output now includes only non-whitelisted entries:

| vuln_id       | url                                            | package   | version | severity | grype | osv | vulnix | sum |
|---------------+------------------------------------------------+-----------+---------+----------+-------+-----+--------+-----|
| CVE-2023-3817 | https://nvd.nist.gov/vuln/detail/CVE-2023-3817 | openssl   | 3.0.9   |   5.3    |   1   |  0  |   1    |  2  |

INFO     Wrote: vulns.csv

# In addition to the console report, vulnxscan writes a detailed report in a csv file,
# by default 'vulns.csv', which includes the full details also from the whitelisted vulnerabilities:
$ csvlook vulns.csv

| vuln_id          | url                                               | package   | version | severity | grype |   osv | vulnix | sum | sortcol         | whitelist | whitelist_comment                                                       |
| ---------------- | ------------------------------------------------- | --------- | ------- | -------- | ----- | ----- | ------ | --- | --------------- | --------- | ----------------------------------------------------------------------- |
| CVE-2023-3817    | https://nvd.nist.gov/vuln/detail/CVE-2023-3817    | openssl   | 3.0.9   |      5.3 |  True | False |   True |   2 | 2023A0000003817 |     False |                                                                         |
| CVE-2022-38663   | https://nvd.nist.gov/vuln/detail/CVE-2022-38663   | git       | 2.41.0  |      6.5 | False | False |   True |   1 | 2022A0000038663 |      True | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| CVE-2022-36884   | https://nvd.nist.gov/vuln/detail/CVE-2022-36884   | git       | 2.41.0  |      5.3 | False | False |   True |   1 | 2022A0000036884 |      True | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| CVE-2022-36883   | https://nvd.nist.gov/vuln/detail/CVE-2022-36883   | git       | 2.41.0  |      7.5 | False | False |   True |   1 | 2022A0000036883 |      True | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| CVE-2022-36882   | https://nvd.nist.gov/vuln/detail/CVE-2022-36882   | git       | 2.41.0  |      8.8 | False | False |   True |   1 | 2022A0000036882 |      True | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| CVE-2022-30949   | https://nvd.nist.gov/vuln/detail/CVE-2022-30949   | git       | 2.41.0  |      5.3 | False | False |   True |   1 | 2022A0000030949 |      True | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| CVE-2022-30948   | https://nvd.nist.gov/vuln/detail/CVE-2022-30948   | git       | 2.41.0  |      7.5 | False | False |   True |   1 | 2022A0000030948 |      True | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| CVE-2022-30947   | https://nvd.nist.gov/vuln/detail/CVE-2022-30947   | git       | 2.41.0  |      7.5 | False | False |   True |   1 | 2022A0000030947 |      True | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| MAL-2022-4301    | https://osv.dev/MAL-2022-4301                     | libidn2   | 2.3.4   |          | False |  True |  False |   1 | 2022A0000004301 |      True | Incorrect package: Issue refers npm libidn2, not libidn2.               |
| CVE-2021-21684   | https://nvd.nist.gov/vuln/detail/CVE-2021-21684   | git       | 2.41.0  |      6.1 | False | False |   True |   1 | 2021A0000021684 |      True | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| CVE-2020-2136    | https://nvd.nist.gov/vuln/detail/CVE-2020-2136    | git       | 2.41.0  |      5.4 | False | False |   True |   1 | 2020A0000002136 |      True | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| CVE-2019-1003010 | https://nvd.nist.gov/vuln/detail/CVE-2019-1003010 | git       | 2.41.0  |      4.3 | False | False |   True |   1 | 2019A0001003010 |      True | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| CVE-2018-1000182 | https://nvd.nist.gov/vuln/detail/CVE-2018-1000182 | git       | 2.41.0  |      6.4 | False | False |   True |   1 | 2018A0001000182 |      True | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| CVE-2018-1000110 | https://nvd.nist.gov/vuln/detail/CVE-2018-1000110 | git       | 2.41.0  |      5.3 | False | False |   True |   1 | 2018A0001000110 |      True | Incorrect package: Impacts Jenkins git plugin, not git.                 |
| CVE-2016-2781    | https://nvd.nist.gov/vuln/detail/CVE-2016-2781    | coreutils | 9.3     |      6.5 |  True | False |  False |   1 | 2016A0000002781 |      True | NVD data issue: CPE entry does not correctly state the version numbers. |
```

See ghafscan [manual_analysis.csv](https://github.com/tiiuae/ghafscan/blob/main/manual_analysis.csv) for a more complete example and usage of the vulnxscan whitelisting feature.

### Find Vulnerabilities Given SBOM as Input
This example shows how to use `vulnxscan` to summarize vulnerabilities impacting components in the given CycloneDX SBOM.

First, we use `sbomnix` to generate SBOM for the example target:
```bash
$ nix run .#sbomnix -- github:NixOS/nixpkgs/nixos-unstable#git
..
INFO     Wrote: sbom.cdx.json
```

Then, give the generated SBOM as input to `vulnxscan`:
```bash
$ vulnxscan --sbom sbom.cdx.json

INFO     Console report

Potential vulnerabilities impacting version_local:

| vuln_id       | url                                            | package   | version | severity | grype | osv | sum |
|---------------+------------------------------------------------+-----------+---------+----------+-------+-----+-----|
| CVE-2023-3817 | https://nvd.nist.gov/vuln/detail/CVE-2023-3817 | openssl   | 3.0.9   | 5.3      |   1   |  0  |  1  |
| CVE-2023-2975 | https://nvd.nist.gov/vuln/detail/CVE-2023-2975 | openssl   | 3.0.9   | 5.3      |   1   |  0  |  1  |
| MAL-2022-4301 | https://osv.dev/MAL-2022-4301                  | libidn2   | 2.3.4   |          |   0   |  1  |  1  |
| CVE-2016-2781 | https://nvd.nist.gov/vuln/detail/CVE-2016-2781 | coreutils | 9.3     | 6.5      |   1   |  0  |  1  |

INFO     Wrote: vulns.csv
```
Notice that `vulnxscan` drops the vulnix scan when the input is SBOM. This is due to the vulnix not supporting SBOM input at the time of writing.

Also notice that `vulnxscan` drops the patch auto-detection if the input is SBOM. Reason is that `vulnxscan` reads the patch information from nix derivations. Therefore, the patch information is only available when the given input is Nix store path (e.g. derivation or out-path), not SBOM.


### Find Vulnerabilities Impacting Buildtime and Runtime Dependencies
By default, `vulnxscan` scans the given target for vulnerabilities that impact its runtime-only dependencies. This example shows how to use `vulnxscan` to include also buildtime dependencies to the scan.

```bash
$ vulnxscan ./result --buildtime

# ... output not included in this snippet ...
```

### Using Whitelist to Record Manual Analysis Results
`vulnxscan` supports using whitelist csv file as a more generic record of manual analysis results, by allowing non-whitelisting rules. That is, the whitelist csv file can include a boolean `whitelist` column to indicate if the matching vulnerabilities should be whitelisted or not. The default value for `whitelist` is True, that is, if the `whitelist` column is missing or the value is empty, `vulnxscan` interprets the rule as if the `whitelist` column value would evaluate to True.

As an example, consider the following manual analysis record (i.e. 'whitelist'):

```
csvlook manual_analysis.csv

| vuln_id        | whitelist | package   | comment                                                            |
| -------------- | --------- | --------- | ------------------------------------------------------------------ |
| CVE-2022-0856  |     False | libcaca   | Not fixed upstream: https://github.com/cacalabs/libcaca/issues/65. |
| CVE-2021-32490 |     False | djvulibre | Pending merge: https://github.com/NixOS/nixpkgs/pull/246773.       |
```

The above example `manual_analysis.csv` includes two rules: one for `CVE-2022-0856` and one for `CVE-2021-32490`. For both, the `whitelist` column value is '`False`', indicating the rule is a non-whitelisting rule. This means, for both cases, we want to record the manual analysis results as detailed in the `comment` column, but we don't want to whitelist the matching vulnerabilities. Specifically, in the case of `CVE-2022-0856` we don't want to whitelist the issue since it's not fixed upstream, but we still want to record the link to the upstream PR to make it easier to follow the upstream progress. In the case of `CVE-2021-32490` we don't want to whitelist the issue since the nixpkgs PR is pending merge. In this case too, we still want to record the nixpkgs PR to allow following the progress.

See ghafscan [manual_analysis.csv](https://github.com/tiiuae/ghafscan/blob/main/manual_analysis.csv) for a more complete example and usage of non-whitelisting rules to help manual analysis.

### Triage to Help Manual Analysis
`vulnxscan` can be used to help manual analysis with `--triage` and `--nixprs` command line options.

With command line option `--triage`, `vulnxscan` queries repology.org for nix-unstable and package upstream version information, as well as the CVE impacted versions. With the additional information from repology.org, `vulnxscan` classifies each vulnerability accordingly.

Consider the following example, using [ghaf](https://github.com/tiiuae/ghaf) as target:

```bash
# Run vulnxscan:
#  --buildtime: Scan buildtime dependencies. Scanning buildtime dependencies does not
#               require building the target, which allows relatively quick scan also for
#               targets not built earlier. Notice: nix 'buildtime' dependencies are a
#               superset of runtime dependencies.
#  --whitelist: Use 'manual_analysis.csv' as a whitelist file.
#  --triage   : Help manual analysis by querying version info from repology.org.
$ vulnxscan github:tiiuae/ghaf?ref=main#packages.x86_64-linux.generic-x86_64-release --buildtime --whitelist=manual_analysis.csv --triage
INFO     Generating SBOM for target '/nix/store/...-nixos-disk-image.drv'
INFO     CVE-2023-27371 for 'libmicrohttpd' is patched with: ['/nix/store/l53sq07v6hghm7cchcjbrwyvjyjag06r-CVE-2023-27371.patch']
INFO     CVE-2023-2975 for 'openssl' is patched with: ['/nix/store/7gz0nj14469r9dlh8p0j5w5wjj3b6hw4-CVE-2023-2975.patch']
INFO     CVE-2023-2975 for 'openssl' is patched with: ['/nix/store/7gz0nj14469r9dlh8p0j5w5wjj3b6hw4-CVE-2023-2975.patch']
INFO     CVE-2023-2975 for 'openssl' is patched with: ['/nix/store/7gz0nj14469r9dlh8p0j5w5wjj3b6hw4-CVE-2023-2975.patch']
INFO     CVE-2023-2975 for 'openssl' is patched with: ['/nix/store/7gz0nj14469r9dlh8p0j5w5wjj3b6hw4-CVE-2023-2975.patch']
INFO     CVE-2023-2617 for 'opencv' is patched with: ['/nix/store/vw29nr5nrfs10vv5p3m7rpkqscwrh4sp-CVE-2023-2617.patch']
...

Potential vulnerabilities impacting version_local:

| vuln_id             | package    | severity | version_local | version_nixpkgs | version_upstream | classify                             |
|---------------------+------------+----------+---------------+-----------------+------------------+--------------------------------------|
| CVE-2023-40360      | qemu       | 5.5      | 8.0.2         | 8.1.0           | 8.1.0            | fix_update_to_version_nixpkgs        |
| CVE-2023-40359      | xterm      | 9.8      | 379           | 384             | 384              | fix_update_to_version_nixpkgs        |
| CVE-2023-39742      | giflib     | 5.5      | 5.2.1         | 5.2.1           | 5.2.1            | fix_not_available                    |
| CVE-2023-39533      | go         | 7.5      | 1.20.6        | 1.21.1          | 1.21.1           | fix_update_to_version_nixpkgs        |
| CVE-2023-38858      | faad2      | 6.5      | 2.10.1        | 2.10.1          | 2.10.1           | fix_not_available                    |
| CVE-2023-38857      | faad2      | 5.5      | 2.10.1        | 2.10.1          | 2.10.1           | fix_not_available                    |
| CVE-2023-38633      | librsvg    | 5.5      | 2.55.1        | 2.56.3          | 2.56.3           | fix_update_to_version_nixpkgs        |
| CVE-2023-37769      | pixman     | 6.5      | 0.42.2        | 0.42.2          | 0.42.2           | err_not_vulnerable_based_on_repology |
| CVE-2023-31484      | perl       | 8.1      | 5.36.0-env    | 5.38.0          | 5.38.0           | fix_update_to_version_nixpkgs        |
| CVE-2023-31484      | perl       | 8.1      | 5.36.0        | 5.38.0          | 5.38.0           | fix_update_to_version_nixpkgs        |
| CVE-2023-30571      | libarchive | 5.3      | 3.6.2         | 3.6.2           | 3.7.1            | fix_update_to_version_upstream       |
| CVE-2023-29409      | go         | 5.3      | 1.20.6        | 1.21.1          | 1.21.1           | fix_update_to_version_nixpkgs        |
| CVE-2023-29383      | shadow     | 3.3      | 4.13          | 4.13            | 4.14.0           | fix_update_to_version_upstream       |

... (output truncated) ...

INFO     Wrote: /home/hrosten/projects/sbomnix-fork/vulns.csv
INFO     Wrote: /home/hrosten/projects/sbomnix-fork/vulns.triage.csv
```

As an example, the output table states the following:
- Package `qemu` 8.0.2, which is a dependency to ghaf, is potentially vulnerable to CVE-2023-40360.
- Based on repology.org, `qemu` newest version in nix-unstable is 8.0.4. Also, based on repology.org, latest `qemu` version in the `qemu` upstream is 8.1.0.
- Since both `qemu` 8.0.2 and 8.0.4 are vulnerable to CVE-2023-40360, but the upstream version 8.1.0 is not vulnerable, `vulnxscan` classifies the issue as `fix_update_to_version_upstream`.
- Package `xterm` version 379 is potentially vulnerable to CVE-2023-40359. Latest version of `xterm` in nix-unstable is 384, which is not vulnerable to CVE-2023-40359. Therefore, `vulnxscan` classifies the issue as `fix_update_to_version_nixpkgs`.
- Package `giflib` version 5.2.1 is potentially vulnerable to CVE-2023-39742. Since there's no known fixed version available in nix-unstable or the package upstream, `vulnxscan` classifies the issue as `fix_not_available`. Notice that the classification is based only on the version numbers. Indeed, it's still possible that there's an upstream patch available in an unreleased version of `giflib` that would fix the issue.
- Package `pixman` version 0.42.2 is potentially vulnerable to CVE-2023-37769. However, based on repology.org, the vulnerability [does not impact](https://repology.org/project/pixman/cves?version=0.42.2) the given version of `pixman`. Therefore, `vulnxscan` classifies the issue as `err_not_vulnerable_based_on_repology`.

##### Nixpkgs PR Search

With command line option `--nixprs`, `vulnxscan` queries github for nixpkgs PRs that might include more information concerning possible nixpkgs fixes for the found vulnerabilities. `--nixprs` adds URLs to (at most five) PRs that appear valid for each vulnerability based on heuristic. The PR search takes significant time due to github API rate limits, which is why it is not enabled by default.

Consider the following example, using the same Ghaf target as earlier:

```bash
# Run vulnscan with --triage and --nixprs
$ vulnxscan github:tiiuae/ghaf?ref=main#packages.x86_64-linux.generic-x86_64-release --buildtime --whitelist=manual_analysis.csv --triage --nixprs
INFO     Generating SBOM for target '/nix/store/...-nixos-disk-image.drv'
...
Potential vulnerabilities impacting version_local:


| vuln_id        | package    | severity   | version_local | version_nixpkgs | version_upstream | classify                      | nixpkgs_pr                                    |
|----------------+------------+------------+---------------+-----------------+------------------+-------------------------------+-----------------------------------------------|
| CVE-2023-40360 | qemu       | 5.5        | 8.0.2         | 8.1.0           | 8.1.0            | fix_update_to_version_nixpkgs | https://github.com/NixOS/nixpkgs/pull/251154  |
| CVE-2023-40359 | xterm      | 9.8        | 379           | 384             | 384              | fix_update_to_version_nixpkgs | https://github.com/NixOS/nixpkgs/pull/244141  |
| CVE-2023-39742 | giflib     | 5.5        | 5.2.1         | 5.2.1           | 5.2.1            | fix_not_available             |                                               |
| CVE-2023-39533 | go         | 7.5        | 1.20.6        | 1.21.1          | 1.21.1           | fix_update_to_version_nixpkgs | https://github.com/NixOS/nixpkgs/pull/253738  |
| CVE-2023-38858 | faad2      | 6.5        | 2.10.1        | 2.10.1          | 2.10.1           | fix_not_available             |                                               |
| CVE-2023-38857 | faad2      | 5.5        | 2.10.1        | 2.10.1          | 2.10.1           | fix_not_available             |                                               |
| CVE-2023-38633 | librsvg    | 5.5        | 2.55.1        | 2.56.3          | 2.56.3           | fix_update_to_version_nixpkgs | https://github.com/NixOS/nixpkgs/pull/246763  |
|                |            |            |               |                 |                  |                               | https://github.com/NixOS/nixpkgs/pull/246860  |
| CVE-2023-37769 | pixman     | 6.5        | 0.42.2        | 0.42.2          | 0.42.2           | err_not_vulnerable_based_on_re|                                               |
| CVE-2023-31484 | perl       | 8.1        | 5.36.0-env    | 5.38.0          | 5.38.0           | fix_update_to_version_nixpkgs | https://github.com/NixOS/nixpkgs/pull/241848  |
|                |            |            |               |                 |                  |                               | https://github.com/NixOS/nixpkgs/pull/247547  |
| CVE-2023-31484 | perl       | 8.1        | 5.36.0        | 5.38.0          | 5.38.0           | fix_update_to_version_nixpkgs | https://github.com/NixOS/nixpkgs/pull/241848  |
|                |            |            |               |                 |                  |                               | https://github.com/NixOS/nixpkgs/pull/247547  |
| CVE-2023-30571 | libarchive | 5.3        | 3.6.2         | 3.6.2           | 3.7.1            | fix_update_to_version_upstream|                                               |
| CVE-2023-29409 | go         | 5.3        | 1.20.6        | 1.21.1          | 1.21.1           | fix_update_to_version_nixpkgs | https://github.com/NixOS/nixpkgs/pull/247034  |
|                |            |            |               |                 |                  |                               | https://github.com/NixOS/nixpkgs/pull/253738  |
| CVE-2023-29383 | shadow     | 3.3        | 4.13          | 4.13            | 4.14.0           | fix_update_to_version_upstream| https://github.com/NixOS/nixpkgs/pull/233924  |
|                |            |            |               |                 |                  |                               | https://github.com/NixOS/nixpkgs/pull/254143  |
```

`vulnxscan` option `--nixprs` adds the column `nixpkgs_pr` to the output, to help manual analysis by listing PRs that appear relevant for the given issue.

### Component Patch Evidence

Patch filtering answers "is this vulnerability patched?" with a single yes or no. That answer is ambiguous when a Nix closure contains several derivations that share a package name and version but differ in patch metadata: one may carry a patch naming the vulnerability while another does not. Component patch evidence records which derivations a finding resolved to, and what the patch metadata of each one says.

Every report row therefore carries these columns, in both the normal and the `--triage` CSV:

| Column | Meaning |
| --- | --- |
| `finding_id` | Stable `sha256:` digest of the canonical `(vuln_id, package, version)` tuple. |
| `evidence_scope` | How the finding was resolved to components: `component_exact`, `component_expanded`, `component_mixed`, or `package_version_only`. |
| `patch_state` | Aggregate verdict: `all_components_match`, `mixed_component_evidence`, `no_component_match`, `metadata_unavailable`, or `package_version_only`. |
| `resolved_component_count` | Number of components the finding resolved to. |
| `vuln_id_patch_name_match_count` | How many of those carry a patch whose file name names the vulnerability. |
| `no_vuln_id_patch_name_match_count` | How many carry no such patch. |
| `metadata_unavailable_count` | How many have missing or unusable patch metadata, including components inferred without derivation metadata. |
| `package_version_only_count` | `1` when no derivation could be resolved at all, otherwise `0`. |

A matching patch file name is evidence that a fix was applied, not proof; equally, an absent patch name is not proof of exposure. Only `all_components_match` suppresses a finding from the report.

#### Writing the evidence report

Option `--evidence-out PATH` writes the full per-component evidence as JSON. Omitting it leaves the existing CSV behavior untouched.

```bash
# Scan buildtime dependencies and record component evidence next to the CSVs
$ vulnxscan github:NixOS/nixpkgs/nixos-unstable#git --buildtime --triage \
    --out=vulns.csv --evidence-out=evidence.json
...
INFO     CVE-2023-2975 for 'openssl' is patched with: ['/nix/store/...-CVE-2023-2975.patch']
INFO     Wrote: vulns.csv
INFO     Wrote: vulns.triage.csv
INFO     Wrote: evidence.json
```

The document is written atomically and validated first, so a partial or internally inconsistent file is never left behind. A successful scan with no findings still writes a valid document with empty arrays, so an empty file can never be confused with a scan that did not run. The top-level shape is:

```json
{
  "schema_version": 1,
  "observations": [],
  "findings": [],
  "components": []
}
```

- `observations` holds one entry per normalized scanner observation, before cross-scanner aggregation: `observation_id`, `finding_id`, `scanner`, `vuln_id`, `package`, `version`, the scanner's own `severity`, `component_ref`, and `resolution` (`exact`, `expanded`, or `unresolved`). Every raw per-scanner severity is retained here, even though the aggregate finding reports only the highest.
- `findings` holds one entry per `(vuln_id, package, version)`, with the aggregate `severity`, sorted unique `scanners`, `url`, `sortcol`, the evidence columns listed above, and `suppressed_by_patch_evidence`.
- `components` holds one entry per resolved component: `finding_id`, `component_id`, sorted `identity_sources` (`scanner_component_ref`, `sbom_package_version_join`, or `unresolved`), `drv_path`, `output_paths`, `pname`, `version`, `patches`, `patch_evidence_state` (`vuln_id_patch_name_match`, `no_vuln_id_patch_name_match`, `metadata_unavailable`, or `package_version_only`), `matching_patch_paths`, and `suppressed_by_patch_evidence`. `drv_path` is the derivation path when metadata is available and the representative runtime output path for an inferred component.

Unlike the CSV reports, the evidence document also contains the findings that patch filtering suppressed, marked `suppressed_by_patch_evidence: true`, so a suppression can be audited rather than silently trusted.

A complete example document is kept as a contract fixture in [tests/resources/vulnxscan_evidence_v1.json](../tests/resources/vulnxscan_evidence_v1.json) and asserted by the test suite.

All counts are non-negative integers, suppression fields are JSON booleans, path and scanner collections are arrays of strings, and unavailable scalars are empty strings rather than `null`.

When the input is an SBOM (`--sbom`) rather than a Nix target, there is no Nix component table to resolve against, so findings are reported as `package_version_only`.

#### Schema evolution

Readers must ignore unknown object fields; every field listed above is required in schema version 1. Adding an optional field keeps version 1. Removing or renaming a required field, changing a field type, changing identity or count semantics, or adding or changing the meaning of an enum value requires incrementing `schema_version`.

## Footnotes and Future Work

For now, consider `vulnxscan` as a demonstration. Some improvement ideas are listed below:
 - Consider adding patch information to SBOM (e.g. via the [pedigree](https://cyclonedx.org/use-cases/#pedigree) attribute) to be able to auto-detect patched vulnerabilities also when the input is SBOM.
 - Vulnerability scanners lack support for parsing the patch data: even if `sbomnix` added the patch data to the output SBOM, we suspect not many vulnerability scanners would read the information. As an example, the following discussion touches this topic on DependencyTrack: https://github.com/DependencyTrack/dependency-track/issues/919.
 - Identifying packages is hard as pointed out in https://discourse.nixos.org/t/the-future-of-the-vulnerability-roundups/22424/5. As an example, CPEs are inaccurate which causes issues in matching vulnerabilities: https://github.com/DependencyTrack/dependency-track/discussions/2290.
 - Nix ecosystem is not supported in OSV: the way `osv.py` makes use of OSV data for Nix targets -- as explained in section [Nix and OSV vulnerability database](#nix-and-osv-vulnerability-database) -- makes the reported OSV vulnerabilities include false positives.

### Other Future Work
- [vulnxscan](../src//vulnxscan/vulnxscan_cli.py) could include more scanners in addition to [vulnix](https://github.com/nix-community/vulnix), [grype](https://github.com/anchore/grype), and [osv.py](../src/vulnxscan/osv.py). Suggestions for other open-source scanners, especially those that can digest CycloneDX or SPDX SBOMs are welcome. Consider e.g. [bombon](https://github.com/nikstur/bombon) and [cve-bin-tool](https://github.com/intel/cve-bin-tool). Adding cve-bin-tool to vulnxscan was [demonstrated](https://github.com/tiiuae/sbomnix/pull/75) earlier, but not merged due to reasons explained in the [PR](https://github.com/tiiuae/sbomnix/pull/75#issuecomment-1670958503).
