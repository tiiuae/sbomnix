# sbomnix

`sbomnix` is a utility that generates SBOMs from nix packages. It uses the dependency scanner from [vulnix](https://github.com/flyingcircusio/vulnix).

## Getting Started
`sbomnix` requires common Nix tools like `nix` and `nix-store`. These tools are expected to be in `$PATH`.

### Running without installation
`sbomnix` requires python3 and packages specified in [requirements.txt](./requirements.txt). You can install the required packages with:
```
$ cd /path/to/sbomnix/
$ pip3 install -r requirements.txt
```
After requirements have been installed, you can run sbomnix with 'python3 -m':
```
$ python3 -m sbomnix.sbomnix 
usage: sbomnix.py [-h] [--verbose VERBOSE] [--runtime] [--meta [META]] [--csv [CSV]] [--cdx [CDX]] NIX_PATH
```

### Installation
Examples in this README.md assume you have installed `sbomnix` on your system and that command `sbomnix` is in `$PATH`. To install `sbomnix` from source, run:
```
$ python3 setup.py install --user
```

## Usage examples
#### Generate SBOM based on derivation file
```
$ sbomnix /nix/store/qcvlk255x98i46cg9vphkdw5pghrizsh-hello-2.12.1.drv
...
INFO     Wrote: sbom.cdx.json
INFO     Wrote: sbom.csv
```

#### Generate SBOM based on derivation file, including meta information
First, generate package meta information json file:
```
$ nix-env -qa --meta --json '.*' >meta.json
```
Use `--meta` to tell sbomnix to read meta information from the given json file:
```
$ sbomnix /nix/store/qcvlk255x98i46cg9vphkdw5pghrizsh-hello-2.12.1.drv --meta meta.json
```

#### Generate SBOM based on derivation file, including only runtime dependencies
Use --runtime to tell sbomnix to only include runtime dependencies to the SBOM:
```
$ sbomnix /nix/store/qcvlk255x98i46cg9vphkdw5pghrizsh-hello-2.12.1.drv --meta meta.json --runtime
```
#### Generate SBOM based on output path (rather than derivation file)
```
$ sbomnix /path/to/result 
```
#### Show help message
```
$ sbomnix --help
```
