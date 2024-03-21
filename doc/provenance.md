<!--
SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Getting Started

To get started, follow the [Getting Started](../README.md#getting-started) section from the main [README](../README.md).

As an example, to run the [`provenance`](../src/provenance/main.py) tool from the `tiiuae/sbomnix` repository:

```bash
# '--' signifies the end of argument list for `nix`.
# '--help' is the first argument to `provenance`
nix run github:tiiuae/sbomnix#provenance -- --help
```

# provenance

[`provenance`](../src/provenance/main.py) is a command line tool to generate SLSA v1.0 compliant [provenance](https://slsa.dev/spec/v1.0/provenance) attestation files in json format for any nix flake or derivation.

To generate provenance file for `nixpkgs#hello`:

```bash
provenance nixpkgs#hello
```

To generate provenance file for `curl-8.6.0` in your nix store:

```bash
provenance /nix/store/fh7vxc5xgiwl6z7vwq5c3lj84mpcs4br-curl-8.6.0-bin
```

By default the dependencies are resolved only at the top level. ie. only direct dependencies.
To get all dependencies recursively, you can use the `--recursive` option.
Note the this will result in a very long provenance file.

The dependencies listed are the nix buildtime dependencies of the derivation.

Example recursive provenance which is saved into a file:

```bash
provenance nixpkgs#hello --recursive -out ./provenance.json
```

## Build metadata

The build metadata to be used in the provenance is supplied through environment variables.
These fields cannot be automatically derived from the nix derivation as they are build platform dependant.

Variable | Type | Explanation
--- | --- | ---
PROVENANCE_BUILD_TYPE | str | Corresponds to SLSA [buildDefinition.buildType](https://slsa.dev/spec/v1.0/provenance#builddefinition)
PROVENANCE_BUILDER_ID | str | Corresponds to SLSA [runDetails.builder.id](https://slsa.dev/spec/v1.0/provenance#builder)
PROVENANCE_INVOCATION_ID | str/int | Corresponds to SLSA [buildMetadata.invocationId](https://slsa.dev/spec/v1.0/provenance#buildmetadata)
PROVENANCE_TIMESTAMP_BEGIN | int (unix timestamp) | Is parsed into SLSA [buildMetadata.startedOn](https://slsa.dev/spec/v1.0/provenance#buildmetadata)
PROVENANCE_TIMESTAMP_FINISHED | int (unix timestamp) | Is parsed into SLSA [buildMetadata.finishedOn](https://slsa.dev/spec/v1.0/provenance#buildmetadata)
PROVENANCE_EXTERNAL_PARAMS | json | Corresponds to SLSA [buildDefinition.externalParameters](https://slsa.dev/spec/v1.0/provenance#builddefinition)
PROVENANCE_INTERNAL_PARAMS | json | Corresponds to SLSA [buildDefinition.internalParameters](https://slsa.dev/spec/v1.0/provenance#builddefinition)
PROVENANCE_OUTPUT_FILE | path | Has the same function as the `--out` argument.

Example usage in a simplified build script:

```bash
target="nixpkgs#hello"

PROVENANCE_TIMESTAMP_BEGIN="$(date +%s)"

nix build $target

PROVENANCE_TIMESTAMP_FINISHED="$(date +%s)"

PROVENANCE_EXTERNAL_PARAMS="$(jq -n --arg target "$target" '$ARGS.named')"
PROVENANCE_INTERNAL_PARAMS="$(jq -n --arg nixVersion "$(nix --version)" '$ARGS.named')"

export PROVENANCE_TIMESTAMP_BEGIN
export PROVENANCE_TIMESTAMP_FINISHED
export PROVENANCE_EXTERNAL_PARAMS
export PROVENANCE_INTERNAL_PARAMS

provenance $target --out ./provenance.json
```
