<!--
SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)

SPDX-License-Identifier: Apache-2.0
-->

# sbomnix

`sbomnix` is a utility that generates SBOMs for [nix](https://nixos.org/) packages.

In addition to `sbomnix` this repository is a home to [nixgraph](./doc/nixgraph.md), a python library and command line utility for querying and visualizing dependency graphs for [nix](https://nixos.org/) packages.

`sbomnix` originates from the [Ghaf](https://github.com/tiiuae/ghaf) project.

Table of Contents
=================

* [Getting Started](#getting-started)
   * [Running without installation](#running-without-installation)
   * [Installation](#installation)
* [Usage examples](#usage-examples)
   * [Generate SBOM based on derivation file](#generate-sbom-based-on-derivation-file)
   * [Generate SBOM including meta information](#generate-sbom-including-meta-information)
   * [Generate SBOM including only runtime dependencies](#generate-sbom-including-only-runtime-dependencies)
   * [Generate SBOM based on output path](#generate-sbom-based-on-output-path)
   * [Visualize package dependencies](#visualize-package-dependencies)
* [Contribute](#contribute)
* [License](#license)
* [Acknowledgements](#acknowledgements)

## Getting Started
`sbomnix` requires common [nix](https://nixos.org/download.html) tools like `nix` and `nix-store`. These tools are expected to be in `$PATH`.
`nixgraph` requires [graphviz](https://graphviz.org/download/).

### Running without installation
`sbomnix` requires python3 and packages specified in [requirements.txt](./requirements.txt). You can install the required packages with:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ pip3 install --user -r requirements.txt
```
After requirements have been installed, you can run sbomnix without installation as follows:
```bash
$ source scripts/env.sh
$ python3 sbomnix/main.py
usage: sbomnix.py [-h] [--verbose VERBOSE] [--runtime] [--meta [META]] [--csv [CSV]] [--cdx [CDX]] NIX_PATH
```

### Installation
Examples in this README.md assume you have installed `sbomnix` on your system and that command `sbomnix` is in `$PATH`. To install `sbomnix` from source, run:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix
$ pip3 install --user .
```

## Usage examples
In the below examples, we use nix package `wget` as an example target.
To install wget and print out its derivation path on your local system, try something like:
```bash
$ nix-env -i wget && nix-env -q -a --drv-path wget
installing 'wget-1.21.3'
wget-1.21.3  /nix/store/1kd6cas7lxhccf7bv1v37wvwmknahfrj-wget-1.21.3.drv
```

#### Generate SBOM based on derivation file
By default `sbomnix` scans the given derivation and generates an SBOM including both buildtime and runtime dependencies:
```bash
$ sbomnix /nix/store/1kd6cas7lxhccf7bv1v37wvwmknahfrj-wget-1.21.3.drv
...
INFO     Wrote: sbom.cdx.json
INFO     Wrote: sbom.csv
```
Main output is the SBOM json file (sbom.cdx.json) in [CycloneDX](https://cyclonedx.org/) format.

#### Generate SBOM including meta information
To include license information to the SBOM, first generate package meta information with `nix-env`:
```bash
$ nix-env -qa --meta --json '.*' >meta.json
```
Then, run `sbomnix` with `--meta` argument to tell sbomnix to read meta information from the given json file:
```bash
$ sbomnix /nix/store/1kd6cas7lxhccf7bv1v37wvwmknahfrj-wget-1.21.3.drv --meta meta.json
```

#### Generate SBOM including only runtime dependencies
Use `--runtime` to tell sbomnix to only include the runtime dependencies to the SBOM:
```bash
$ sbomnix /nix/store/1kd6cas7lxhccf7bv1v37wvwmknahfrj-wget-1.21.3.drv --meta meta.json --runtime
```
#### Generate SBOM based on output path
`sbomnix` can be used with output paths too (e.g. anything which produces a result symlink):
```bash
$ sbomnix /path/to/result 
```
#### Visualize package dependencies
`sbomnix` finds the package dependencies using `nixgraph`. 
Moreover, `nixgraph` can also be used as a stand-alone tool for visualizing package dependencies.
Below, we show an example of visualizing package `wget` runtime dependencies:
```bash
$ nixgraph /nix/store/1kd6cas7lxhccf7bv1v37wvwmknahfrj-wget-1.21.3.drv --depth=2
```

Which outputs the dependency graph as an image (with maxdepth 2):

<img src="doc/img/wget_runtime.svg" width="900">

For more examples on querying and visualizing the package dependencies, see: [nixgraph](./doc/nixgraph.md).

## Contribute
Any pull requests, suggestions, and error reports are welcome.
To start development, we recommend using lightweight [virtual environments](https://docs.python.org/3/library/venv.html) by running the following commands:
```bash
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix/
$ python3 -mvenv venv
$ source venv/bin/activate
$ source scripts/env.sh
$ make install-dev
```
Run `make help` to see the list of other make targets.
Prior to sending any pull requests, make sure at least the `make pre-push` runs without failures.

To deactivate the virtualenv, run `deactivate` in your shell.


## License
This project is licensed under the Apache-2.0 license - see the [Apache-2.0.txt](LICENSES/Apache-2.0.txt) file for details.


## Acknowledgements
`sbomnix` uses nix store derivation scanner ([nix.py](sbomnix/nix.py) and [derivation.py](sbomnix/derivation.py)) originally from [vulnix](https://github.com/flyingcircusio/vulnix).
