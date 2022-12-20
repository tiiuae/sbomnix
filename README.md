<!--
SPDX-FileCopyrightText: 2022 Technology Innovation Institute (TII)

SPDX-License-Identifier: Apache-2.0
-->

# sbomnix

`sbomnix` is a utility that generates SBOMs from nix packages. It uses the dependency scanner from [vulnix](https://github.com/flyingcircusio/vulnix).

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
   * [Show help message](#show-help-message)
* [Contribute](#contribute)
* [License](#license)

## Getting Started
`sbomnix` requires common Nix tools like `nix` and `nix-store`. These tools are expected to be in `$PATH`.

### Running without installation
`sbomnix` requires python3 and packages specified in [requirements.txt](./requirements.txt). You can install the required packages with:
```
$ cd /path/to/sbomnix/
$ pip3 install -r requirements.txt
```
After requirements have been installed, you can run sbomnix:
```
$ cd /path/to/sbomnix/
# Add sbomnix to PYTHONPATH if needed: 
$ echo :"$PYTHONPATH": | grep :"$(pwd)": || export PYTHONPATH="${PYTHONPATH}:$(pwd)"
$ python3 sbomnix/main.py
usage: sbomnix.py [-h] [--verbose VERBOSE] [--runtime] [--meta [META]] [--csv [CSV]] [--cdx [CDX]] NIX_PATH
```

### Installation
Examples in this README.md assume you have installed `sbomnix` on your system and that command `sbomnix` is in `$PATH`. To install `sbomnix` from source, run:
```
$ cd /path/to/sbomnix/
$ pip3 install --user .
```

## Usage examples
#### Generate SBOM based on derivation file
By default `sbomnix` scans the given derivation and generates an SBOM including both buildtime and runtime dependencies:
```
$ sbomnix /nix/store/qcvlk255x98i46cg9vphkdw5pghrizsh-hello-2.12.1.drv
...
INFO     Wrote: sbom.cdx.json
INFO     Wrote: sbom.csv
```
Main output is the SBOM json file (sbom.cdx.json) in [CycloneDX](https://cyclonedx.org/) format.

#### Generate SBOM including meta information
To include license information to the SBOM, first generate package meta information with `nix-env`:
```
$ nix-env -qa --meta --json '.*' >meta.json
```
Then, run `sbomnix` with `--meta` argument to tell sbomnix to read meta information from the given json file:
```
$ sbomnix /nix/store/qcvlk255x98i46cg9vphkdw5pghrizsh-hello-2.12.1.drv --meta meta.json
```

#### Generate SBOM including only runtime dependencies
Use `--runtime` to tell sbomnix to only include the runtime dependencies to the SBOM:
```
$ sbomnix /nix/store/qcvlk255x98i46cg9vphkdw5pghrizsh-hello-2.12.1.drv --meta meta.json --runtime
```
#### Generate SBOM based on output path
`sbomnix` can be used with output paths too (e.g. anything which produces a result symlink):
```
$ sbomnix /path/to/result 
```
#### Show help message
```
$ sbomnix --help
```

## Contribute
Any pull requests, suggestions, and error reports are welcome.
To start development, we recommend using lightweight [virtual environments](https://docs.python.org/3/library/venv.html) by running the following commands:
```
$ git clone https://github.com/tiiuae/sbomnix
$ cd sbomnix/
$ python3 -mvenv venv
$ source venv/bin/activate
$ pip3 install -e .
```
Next, run `make install-requirements` to set up the virtualenv:
```
$ make install-requirements
```
Run `make help` to see the list of other make targets.
Prior to sending any pull requests, make sure at least the `make pre-push` runs without failures.

To deactivate the virtualenv, run `deactivate` in your shell.


## License
This project is licensed under the Apache-2.0 license - see the [Apache-2.0.txt](LICENSES/Apache-2.0.txt) file for details.
