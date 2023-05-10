<!--
SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# sbomnix

`sbomnix` is a utility that generates SBOMs given [Nix](https://nixos.org/) derivations or out paths.

In addition to `sbomnix` this repository is home to [nixgraph](./doc/nixgraph.md) - a Python library and command line utility for querying and visualizing dependency graphs for [Nix](https://nixos.org/) Packages.

For a demonstration of how to use `sbomnix` generated SBOM in automating vulnerability scans, see: [vulnxscan](scripts/vulnxscan/README.md).

The [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.github.io/spdx-spec/v2.3/) SBOMs for each release of `sbomnix` itself are available in the [release assets](https://github.com/tiiuae/sbomnix/releases/latest).

`sbomnix` and other tools in this repository originate from [Ghaf Framework](https://github.com/tiiuae/ghaf).

Table of Contents
=================

* [Getting Started](#getting-started)
   * [Running Without Installation](#running-without-installation)
      * [Running as Nix Flake](#running-as-nix-flake)
      * [Running as Python Script](#running-as-python-script)
   * [Installation](#installation)
* [Usage Examples](#usage-examples)
   * [Generate SBOM Based on Derivation File or Out-path](#generate-sbom-based-on-derivation-file-or-out-path)
   * [Generate SBOM Including Meta Information](#generate-sbom-including-meta-information)
   * [Generate SBOM Including Buildtime Dependencies](#generate-sbom-including-buildtime-dependencies)
   * [Generate SBOM Based on Result Symlink](#generate-sbom-based-on-result-symlink)
   * [Visualize Package Dependencies](#visualize-package-dependencies)
* [Contribute](#contribute)
* [License](#license)
* [Acknowledgements](#acknowledgements)

## Getting Started
`sbomnix` requires common [Nix](https://nixos.org/download.html) tools like `nix` and `nix-store`. These tools are expected to be in `$PATH`.
`nixgraph` requires [graphviz](https://graphviz.org/download/).

### Running Without Installation
#### Running as Nix Flake
`sbomnix` can be run as a [Nix flake](https://nixos.wiki/wiki/Flakes) from the `tiiuae/sbomnix` repository:
```bash
# '--' signifies the end of argument list for `nix`.
# '--help' is the first argument to `sbomnix`
$ nix run github:tiiuae/sbomnix#sbomnix -- --help
```

or from a local repository:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ nix run .#sbomnix -- --help
```
Similarly, you can run `nixgraph` with `nix run github:tiiuae/sbomnix#nixgraph --  --help`

See the full list of supported flake targets by running `nix flake show`.

#### Running as Python Script
Running `sbomnix` as Python script requires Python packages specified in [requirements.txt](./requirements.txt). You can install the required packages with:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ pip install --user -r requirements.txt
```
After requirements have been installed, you can run sbomnix without installation as follows:
```bash
$ source scripts/env.sh
$ python3 sbomnix/main.py
usage: main.py [-h] [--version] [--verbose VERBOSE] [--meta [META]] [--type {runtime,buildtime,both}] [--csv [CSV]] [--cdx [CDX]] NIX_PATH
```

### Installation
Examples in this README.md assume you have installed `sbomnix` on your system and that command `sbomnix` is in `$PATH`. To install `sbomnix` from source, run:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ nix-env -f default.nix --install
# To uninstall:  nix-env --uninstall '.*sbomnix.*'
```

## Usage Examples
In the below examples, we use Nix package `wget` as an example target.
To install wget and print out its out-path on your local system, try something like:
```bash
$ nix-shell -p wget --run exit && nix eval -f '<nixpkgs>' 'wget.outPath'
"/nix/store/8nbv1drmvh588pwiwsxa47iprzlgwx6j-wget-1.21.3"
```

#### Generate SBOM Based on Derivation File or Out-path
By default `sbomnix` scans the given target and generates an SBOM including the runtime dependencies:
```bash
$ sbomnix /nix/store/8nbv1drmvh588pwiwsxa47iprzlgwx6j-wget-1.21.3
...
INFO     Wrote: sbom.cdx.json
INFO     Wrote: sbom.spdx.json
INFO     Wrote: sbom.csv
```
Main output are the SBOM json files sbom.cdx.json and sbom.spdx.json in [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.github.io/spdx-spec/v2.3/) formats.

#### Generate SBOM Including Meta Information
To include license information to the SBOM, first generate package meta information with `nix-env`:
```bash
$ nix-env -qa --meta --json '.*' >meta.json
```
Then, run `sbomnix` with `--meta` argument to tell sbomnix to read meta information from the given json file:
```bash
$ sbomnix /nix/store/8nbv1drmvh588pwiwsxa47iprzlgwx6j-wget-1.21.3 --meta meta.json
```

#### Generate SBOM Including Buildtime Dependencies
By default `sbomnix` scans the given target for runtime dependencies. You can tell sbomnix to include buildtime dependencies using the `--type` argument. 
Acceptable values for `--type` are `runtime, buildtime, both`. Below example generates SBOM including buildtime-only dependencies:
```bash
$ sbomnix /nix/store/8nbv1drmvh588pwiwsxa47iprzlgwx6j-wget-1.21.3 --meta meta.json --type=buildtime
```
#### Generate SBOM Based on Result Symlink
`sbomnix` can be used with output paths too (e.g. anything which produces a result symlink):
```bash
$ sbomnix /path/to/result 
```
#### Visualize Package Dependencies
`sbomnix` finds the package dependencies using `nixgraph`. 
Moreover, `nixgraph` can also be used as a stand-alone tool for visualizing package dependencies.
Below, we show an example of visualizing package `wget` runtime dependencies:
```bash
$ nixgraph /nix/store/8nbv1drmvh588pwiwsxa47iprzlgwx6j-wget-1.21.3 --depth=2
```

Which outputs the dependency graph as an image (with maxdepth 2):

<img src="doc/img/wget_runtime.svg" width="900">

For more examples on querying and visualizing the package dependencies, see: [nixgraph](./doc/nixgraph.md).

## Contribute
Any pull requests, suggestions, and error reports are welcome.
To start development, we recommend using Nix flakes development shell:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix/
$ nix develop
```
Run `make help` to see the list of supported make targets.
Prior to sending any pull requests, make sure at least the `make pre-push` runs without failures.

To deactivate the Nix devshell, run `exit` in your shell.
To see other Nix flake targets, run `nix flake show`.


## License
This project is licensed under the Apache-2.0 license - see the [Apache-2.0.txt](LICENSES/Apache-2.0.txt) file for details.


## Acknowledgements
`sbomnix` uses Nix store derivation scanner ([nix.py](sbomnix/nix.py) and [derivation.py](sbomnix/derivation.py)) originally from [vulnix](https://github.com/flyingcircusio/vulnix).
