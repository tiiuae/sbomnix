<!--
SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)

SPDX-License-Identifier: Apache-2.0
-->

# vulnxscan

`vulnxscan` is a command line utility that demonstrates automating vulnerability scanning for nix targets.

Table of Contents
=================
* [Getting Started](#getting-started)
* [Usage Examples](#usage-examples)
   * [Example: finding OSV vulnerabilities for nix target](#example-finding-osv-vulnerabilities-for-nix-target)
   * [Example: automating nix vulnerability scans](#example-automating-nix-vulnerability-scans)

## Getting Started
To get started, follow the [Getting Started](../../README.md#getting-started) section from the main [README](../../README.md).

## Usage Examples
In the below examples, we use nix package `git` as an example target.
To install nix `git` package and print out its out-path on your local system, try something like:
```bash
nix-shell -p git --run exit && nix eval -f '<nixpkgs>' 'git.outPath'
```
Which outputs the example target out-path on your local system:
```
==> out-path: /nix/store/5207hz4f779nz4z62zaa5gdjqzqz1l4g-git-2.39.0
```

#### Example: finding OSV vulnerabilities for nix target
This example demonstrates using `osv.py` to manually find vulnerabilities for nix target (derivation or out path).

First, create an SBOM for the target package with `sbomnix`:
```bash
$ sbomnix /nix/store/5207hz4f779nz4z62zaa5gdjqzqz1l4g-git-2.39.0 --type=both
...
INFO     Wrote: sbom.cdx.json
```
`sbomnix` output '`sbom.cdx.json`' is a CycloneDX SBOM including all the dependencies for the target package.
Since we specified `--type=both`, `sbomnix` created SBOM that includes both buildtime and runtime dependencies for the target package 'git-2.39.0'.

To scan the components listed in `sbom.cdx.json` for [OSV](https://osv.dev/list?ecosystem=) vulnerabilities, run `osv.py` specifying the `sbom.cdx.json` as its input:
```bash
$ scripts/vulnxscan/osv.py sbom.cdx.json 
INFO     Parsing sbom: sbom.cdx.json
INFO     Querying vulnerabilities
INFO     Wrote: osv.csv
```
By default, `osv.py` creates a file '`osv.csv`' that lists the [OSV](https://osv.dev/list?ecosystem=) vulnerabilities for components in the given target SBOM '`sbom.cdx.json`':
```bash
$ cat osv.csv | csvlook
| vuln_id             |                         modified | package    | version           |
| ------------------- | -------------------------------- | ---------- | ----------------- |
| CVE-2022-38533      | 2022-12-08 07:35:23.673999+00:00 | binutils   | 2.39              |
| CVE-2022-38533      | 2022-12-08 07:35:23.673999+00:00 | binutils   | 2.39              |
| OSV-2022-1193       | 2022-11-22 13:02:17.631547+00:00 | libarchive | 3.6.2             |
| OSV-2021-777        | 2022-10-15 00:07:59.224833+00:00 | libxml2    | 2.10.3            |
| GHSA-w596-4wvx-j9j6 | 2023-01-10 06:31:12.168658+00:00 | py         | 1.11.0            |
| PYSEC-2022-42969    |        2022-11-04 11:00:00+00:00 | py         | 1.11.0            |
| CVE-2021-4217       | 2022-11-29 18:47:35.076862+00:00 | unzip      | 6.0               |
| CVE-2022-0529       | 2022-11-22 20:50:58.853135+00:00 | unzip      | 6.0               |
| CVE-2022-0530       | 2022-11-22 20:51:04.133769+00:00 | unzip      | 6.0               |
| OSV-2022-193        | 2023-01-22 00:12:25.178113+00:00 | w3m        | 0.5.3+git20220429 |
| GHSA-qwmp-2cf2-g9g6 | 2023-01-10 05:51:07.299424+00:00 | wheel      | 0.37.1            |
```

*Note (1)*: since we gave `osv.py` an input SBOM that includes both buildtime and runtime dependencies, `osv.py` lists vulnerabilities for both buildtime and runtime dependencies. To find vulnerabilities that impact only runtime dependencies, create the input SBOM with `--type=runtime`.

*Note (2)*: `osv.py`: demonstrates querying OSV data given CycloneDX SBOM as input. [OSV](https://osv.dev/list?ecosystem=) database [currently does not support nix ecosystem](https://ossf.github.io/osv-schema/#affectedpackage-field), so queries that specify nix as ecosystem would not return any matches. Therefore, for demonstration, `osv.py` sends queries to [OSV API](https://osv.dev/docs/) without specifying the ecosystem, only the package name and version. At the time of writing, such queries return vulnerabilities that match the given package and version across all ecosystems, although, this feature seems to be undocumented in the [API specification](https://osv.dev/docs/#tag/api/operation/OSV_QueryAffected). As a result, the returned vulnerabilities are inaccurate and might not be valid for the nix ecosystem.

#### Example: automating nix vulnerability scans
This example shows how to use `vulnxscan.py` to summarize vulnerabilities for the given target with different scanners.

To find vulnerabilities that potentially impact 'git-2.39.0' or some of its runtime or buildtime dependencies, run `vulnxscan.py` as follows:
```bash
$ scripts/vulnxscan/vulnxscan.py /nix/store/5207hz4f779nz4z62zaa5gdjqzqz1l4g-git-2.39.0 --buildtime
INFO     Checking nix installation
INFO     Generating SBOM for target '/nix/store/5207hz4f779nz4z62zaa5gdjqzqz1l4g-git-2.39.0'
INFO     Running vulnix scan
INFO     Running grype scan
INFO     Running OSV scan
INFO     Writing report
INFO     Console report:

Potential vulnerabilities impacting '/nix/store/5207hz4f779nz4z62zaa5gdjqzqz1l4g-git-2.39.0' or some of its runtime or buildtime dependencies:

| vuln_id             | url                                               | package    | version          |  grype  |  osv  |  vulnix  |  sum  |
|---------------------+---------------------------------------------------+------------+------------------+---------+-------+----------+-------|
| GHSA-w596-4wvx-j9j6 | https://osv.dev/GHSA-w596-4wvx-j9j6               | py         | 1.11.0           |    0    |   1   |    0     |   1   |
| GHSA-qwmp-2cf2-g9g6 | https://osv.dev/GHSA-qwmp-2cf2-g9g6               | wheel      | 0.37.1           |    0    |   1   |    0     |   1   |
| CVE-2022-42969      | https://nvd.nist.gov/vuln/detail/CVE-2022-42969   | py         | 1.11.0           |    1    |   0   |    0     |   1   |
| PYSEC-2022-42969    | https://osv.dev/PYSEC-2022-42969                  | py         | 1.11.0           |    0    |   1   |    0     |   1   |
| CVE-2022-41953      | https://nvd.nist.gov/vuln/detail/CVE-2022-41953   | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2022-41903      | https://nvd.nist.gov/vuln/detail/CVE-2022-41903   | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2022-40898      | https://nvd.nist.gov/vuln/detail/CVE-2022-40898   | wheel      | 0.37.1-source    |    0    |   0   |    1     |   1   |
| CVE-2022-38663      | https://nvd.nist.gov/vuln/detail/CVE-2022-38663   | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2022-38533      | https://nvd.nist.gov/vuln/detail/CVE-2022-38533   | binutils   | 2.39             |    1    |   1   |    1     |   3   |
| CVE-2022-38223      | https://nvd.nist.gov/vuln/detail/CVE-2022-38223   | w3m        | 0.5.3+git2022042 |    1    |   0   |    0     |   1   |
| CVE-2022-36884      | https://nvd.nist.gov/vuln/detail/CVE-2022-36884   | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2022-36883      | https://nvd.nist.gov/vuln/detail/CVE-2022-36883   | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2022-36882      | https://nvd.nist.gov/vuln/detail/CVE-2022-36882   | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2022-30949      | https://nvd.nist.gov/vuln/detail/CVE-2022-30949   | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2022-30948      | https://nvd.nist.gov/vuln/detail/CVE-2022-30948   | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2022-30947      | https://nvd.nist.gov/vuln/detail/CVE-2022-30947   | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2022-28321      | https://nvd.nist.gov/vuln/detail/CVE-2022-28321   | linux-pam  | 1.5.2            |    0    |   0   |    1     |   1   |
| CVE-2022-23521      | https://nvd.nist.gov/vuln/detail/CVE-2022-23521   | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2022-3996       | https://nvd.nist.gov/vuln/detail/CVE-2022-3996    | openssl    | 3.0.7            |    1    |   0   |    0     |   1   |
| CVE-2022-1304       | https://nvd.nist.gov/vuln/detail/CVE-2022-1304    | e2fsprogs  | 1.46.5           |    1    |   0   |    0     |   1   |
| OSV-2022-1193       | https://osv.dev/OSV-2022-1193                     | libarchive | 3.6.2            |    0    |   1   |    0     |   1   |
| CVE-2022-0530       | https://nvd.nist.gov/vuln/detail/CVE-2022-0530    | unzip      | 6.0              |    0    |   1   |    1     |   2   |
| CVE-2022-0529       | https://nvd.nist.gov/vuln/detail/CVE-2022-0529    | unzip      | 6.0              |    0    |   1   |    1     |   2   |
| OSV-2022-193        | https://osv.dev/OSV-2022-193                      | w3m        | 0.5.3+git2022042 |    0    |   1   |    0     |   1   |
| CVE-2021-38185      | https://nvd.nist.gov/vuln/detail/CVE-2021-38185   | cpio       | 2.13             |    1    |   0   |    0     |   1   |
| CVE-2021-35331      | https://nvd.nist.gov/vuln/detail/CVE-2021-35331   | tcl        | 8.6.11           |    1    |   0   |    1     |   2   |
| CVE-2021-21684      | https://nvd.nist.gov/vuln/detail/CVE-2021-21684   | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2021-4217       | https://nvd.nist.gov/vuln/detail/CVE-2021-4217    | unzip      | 6.0              |    0    |   1   |    1     |   2   |
| OSV-2021-777        | https://osv.dev/OSV-2021-777                      | libxml2    | 2.10.3           |    0    |   1   |    0     |   1   |
| CVE-2020-2136       | https://nvd.nist.gov/vuln/detail/CVE-2020-2136    | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2019-1003010    | https://nvd.nist.gov/vuln/detail/CVE-2019-1003010 | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2019-20633      | https://nvd.nist.gov/vuln/detail/CVE-2019-20633   | patch      | 2.7.6            |    1    |   0   |    1     |   2   |
| CVE-2019-14900      | https://nvd.nist.gov/vuln/detail/CVE-2019-14900   | fuse       | 3.11.0           |    0    |   0   |    1     |   1   |
| CVE-2019-14900      | https://nvd.nist.gov/vuln/detail/CVE-2019-14900   | fuse       | 2.9.9-closefrom- |    0    |   0   |    1     |   1   |
| CVE-2019-14900      | https://nvd.nist.gov/vuln/detail/CVE-2019-14900   | fuse       | 2.9.9            |    0    |   0   |    1     |   1   |
| CVE-2019-14860      | https://nvd.nist.gov/vuln/detail/CVE-2019-14860   | fuse       | 3.11.0           |    0    |   0   |    1     |   1   |
| CVE-2019-14860      | https://nvd.nist.gov/vuln/detail/CVE-2019-14860   | fuse       | 2.9.9-closefrom- |    0    |   0   |    1     |   1   |
| CVE-2019-14860      | https://nvd.nist.gov/vuln/detail/CVE-2019-14860   | fuse       | 2.9.9            |    0    |   0   |    1     |   1   |
| CVE-2019-13638      | https://nvd.nist.gov/vuln/detail/CVE-2019-13638   | patch      | 2.7.6            |    1    |   0   |    0     |   1   |
| CVE-2019-13636      | https://nvd.nist.gov/vuln/detail/CVE-2019-13636   | patch      | 2.7.6            |    1    |   0   |    0     |   1   |
| CVE-2019-6293       | https://nvd.nist.gov/vuln/detail/CVE-2019-6293    | flex       | 2.6.4            |    0    |   0   |    1     |   1   |
| CVE-2018-1000182    | https://nvd.nist.gov/vuln/detail/CVE-2018-1000182 | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2018-1000156    | https://nvd.nist.gov/vuln/detail/CVE-2018-1000156 | patch      | 2.7.6            |    1    |   0   |    0     |   1   |
| CVE-2018-1000110    | https://nvd.nist.gov/vuln/detail/CVE-2018-1000110 | git        | 2.39.0           |    0    |   0   |    1     |   1   |
| CVE-2018-1000097    | https://nvd.nist.gov/vuln/detail/CVE-2018-1000097 | sharutils  | 4.15.2           |    1    |   0   |    0     |   1   |
| CVE-2018-20969      | https://nvd.nist.gov/vuln/detail/CVE-2018-20969   | patch      | 2.7.6            |    1    |   0   |    0     |   1   |
| CVE-2018-20225      | https://nvd.nist.gov/vuln/detail/CVE-2018-20225   | pip        | 22.3.1           |    1    |   0   |    0     |   1   |
| CVE-2018-6952       | https://nvd.nist.gov/vuln/detail/CVE-2018-6952    | patch      | 2.7.6            |    1    |   0   |    0     |   1   |
| CVE-2018-6951       | https://nvd.nist.gov/vuln/detail/CVE-2018-6951    | patch      | 2.7.6            |    1    |   0   |    0     |   1   |
| CVE-2018-6198       | https://nvd.nist.gov/vuln/detail/CVE-2018-6198    | w3m        | 0.5.3+git2022042 |    1    |   0   |    0     |   1   |
| CVE-2018-6197       | https://nvd.nist.gov/vuln/detail/CVE-2018-6197    | w3m        | 0.5.3+git2022042 |    1    |   0   |    0     |   1   |
| CVE-2018-6196       | https://nvd.nist.gov/vuln/detail/CVE-2018-6196    | w3m        | 0.5.3+git2022042 |    1    |   0   |    0     |   1   |
| CVE-2016-2781       | https://nvd.nist.gov/vuln/detail/CVE-2016-2781    | coreutils  | 9.1              |    1    |   0   |    0     |   1   |
| CVE-2010-4226       | https://nvd.nist.gov/vuln/detail/CVE-2010-4226    | cpio       | 2.13             |    1    |   0   |    0     |   1   |

INFO     Wrote: vulns.csv
```

As printed in the console output, `vulnxscan.py` first creates an SBOM, then feeds the SBOM or target path as input to different vulnerability scanners: [vulnix](https://github.com/flyingcircusio/vulnix) (for reference), [grype](https://github.com/anchore/grype), and [osv.py](https://github.com/tiiuae/sbomnix/blob/main/scripts/vulnxscan/osv.py) and creates a summary report. The summary report lists the newest vulnerabilities on top, with the `sum` column indicating how many scanners agreed with the exact same finding. In addition to the console output, `vulnxscan.py` writes the report to csv-file to allow easier post-processing of the output.

*Note (1)*: the above example specified '`--buildtime`' argument, so the output includes vulnerabilities that impact any of the buildtime or runtime dependencies. To get a list of vulnerabilities that impact only runtime dependencies, simply leave out the '`--buildtime`' argument.

*Note (2)*: for now, consider `vulnxscan.py` as a demonstration. The list of reported vulnerabilities is inaccurate for various reasons:
 - `sbomnix` currently does not include the information about applied patches to the CycloneDX SBOM. `sbomnix` collects the list of patches applied on top of each package and outputs the collected data in its csv output, but it does not add the information to the cdx SBOM. CycloneDX apparently would support such information via the [pedigree](https://cyclonedx.org/use-cases/#pedigree) attribute.
 - Vulnerability scanners lack support for parsing the patch data: even if `sbomnix` added the patch data to the output SBOM, we suspect not many vulnerability scanners would read the information. As an example, the following discussion touches this topic on DependencyTrack: https://github.com/DependencyTrack/dependency-track/issues/919.
 - Identifying packages is hard as pointed out in https://discourse.nixos.org/t/the-future-of-the-vulnerability-roundups/22424/5. As an example, CPEs are inaccurate which causes issues in matching vulnerabilities: https://github.com/DependencyTrack/dependency-track/discussions/2290.
 - Nix ecosystem is not supported in OSV: the way `osv.py` makes use of OSV data for nix targets (as explained in section [Example: finding OSV vulnerabilities for nix target](#example-finding-osv-vulnerabilities-for-nix-target)), makes the reported OSV vulnerabilities inaccurate.

It's a topic of further work to improve the accuracy of the reported vulnerabilities.
