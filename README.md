# sbomnix

`sbomnix` is a utility that generates SBOMs from nix packages. It uses the dependency scanner from [vulnix](https://github.com/flyingcircusio/vulnix).

## Getting Started
`sbomnix` requires common Nix tools like `nix` and `nix-store`. These tools are expected to be in `$PATH`.

### Running without installing
`sbomnix` requires python3 and packages specified in [requirements.txt](./requirements.txt). You can install the required packages with:
```
# Install requirements:
$ cd /path/to/sbomnix/
$ pip3 install -r requirements.txt

# After requirements have been installed, run sbomnix with '-m':
$ python3 -m sbomnix.sbomnix 
usage: sbomnix.py [-h] [--verbose VERBOSE] [--runtime] [--meta [META]] [--csv [CSV]] [--cdx [CDX]] NIX_PATH
```

### Installation
This README.md assumes you have installed `sbomnix` on your system. To install the tools from source, run:
```
$ python3 setup.py install --user
```

## Usage examples
Generate SBOM based on derivation file:
```
$ sbomnix /nix/store/qcvlk255x98i46cg9vphkdw5pghrizsh-hello-2.12.1.drv
INFO     Loading derivations referenced by "/nix/store/qcvlk255x98i46cg9vphkdw5pghrizsh-hello-2.12.1.drv"
WARNING  Command line argument '--meta' missing: SBOM will not include license information
INFO     Wrote: sbom.cdx.json
INFO     Wrote: sbom.csv
```
Generate SBOM based on derivation file, including meta (license) information:
```
# First, generate meta information:
$ nix-env -qa --meta --json '.*' >meta.json

# Use --meta to tell sbomnix to read meta information from the json file
$ sbomnix /nix/store/qcvlk255x98i46cg9vphkdw5pghrizsh-hello-2.12.1.drv --meta meta.json
INFO     Loading derivations referenced by "/nix/store/qcvlk255x98i46cg9vphkdw5pghrizsh-hello-2.12.1.drv"
INFO     Loading meta info from "meta.json"
INFO     Wrote: sbom.cdx.json
INFO     Wrote: sbom.csv
```
Generate SBOM based on derivation file, including meta (license) information. Only include runtime dependencies to the SBOM:
```
# Use --runtime to tell sbomnix to only include runtime dependencies
$ sbomnix /nix/store/qcvlk255x98i46cg9vphkdw5pghrizsh-hello-2.12.1.drv --meta meta.json --runtime
INFO     Loading derivations referenced by "/nix/store/qcvlk255x98i46cg9vphkdw5pghrizsh-hello-2.12.1.drv"
INFO     Loading meta info from "meta.json"
INFO     Wrote: sbom.cdx.json
INFO     Wrote: sbom.csv
```
Generate SBOM based on output path:
```
$ sbomnix /path/to/result 
```
Show help message:
```
$ sbomnix --help
```
