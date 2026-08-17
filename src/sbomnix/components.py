#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""SBOM component dataframe helpers."""

import re

import pandas as pd

from common import columns as cols
from common.log import LOG
from sbomnix.artifacts import is_non_package_artifact_name
from sbomnix.closure import store_path_label
from sbomnix.cpe import CPE
from sbomnix.derivation import load_many, nix_purl

_VERSIONED_NAME_RE = re.compile(
    r"^(?P<pname>.+?)-"
    r"(?P<version>(?:(?:git|unstable)-)?v?[0-9].*?)"
    r"(?:\+abi=[0-9.]+)?"
    r"(?:-(?:bin|data|debug|dev|devdoc|devman|dev_private|dist|dnsutils|doc|"
    r"drivers|env|fonts|getent|gsettings-schemas|host|info|installedTests|lib|"
    r"libgcc|man|modules-shrunk|modules|only-plugins-qml|py|sandbox|scripts|"
    r"sessions|static|su|symbols|wrapped|xz|zstd))?$"
)


def recursive_derivations_to_dataframe(paths, derivations, include_cpe=True):
    """Return component rows from an already-loaded derivation closure."""
    drvs = []
    for path in sorted(paths):
        drv = derivations.get(path)
        if not drv:
            LOG.debug("Recursive buildtime closure missing path: %s", path)
            continue
        drvs.append(drv)
    return _derivations_to_dataframe(drvs, CPE(include_cpe=include_cpe))


def runtime_derivations_to_dataframe(
    paths, output_paths_by_load_path, include_cpe=True
):
    """Return component rows from runtime output-to-load-path mappings."""
    filtered_outputs_by_load_path = filter_runtime_outputs_by_load_path(
        paths,
        output_paths_by_load_path,
    )
    load_paths = sorted(filtered_outputs_by_load_path)
    derivations = list(
        load_many(
            load_paths,
            output_paths_by_drv=filtered_outputs_by_load_path,
            ignore_missing=True,
        ).values()
    )
    cpe_generator = CPE(include_cpe=include_cpe)
    df_derivations = _derivations_to_dataframe(derivations, cpe_generator)
    rows = _inferred_component_rows(
        load_paths,
        filtered_outputs_by_load_path,
        {output_path for drv in derivations for output_path in drv.outputs},
        cpe_generator,
    )
    if not rows:
        return df_derivations
    rows = _drop_alias_rows(rows, df_derivations)
    LOG.info(
        "Inferred %d runtime component(s) from output paths without derivation metadata",
        len(rows),
    )
    return pd.concat(
        [df_derivations, pd.DataFrame.from_records(rows)], ignore_index=True
    )


def _inferred_component_rows(
    load_paths, outputs_by_load_path, loaded_outputs, cpe_generator
):
    """Return conservative component rows for outputs without derivations."""
    rows = []
    for load_path in load_paths:
        output_paths = sorted(outputs_by_load_path[load_path] - loaded_outputs)
        if not output_paths:
            continue
        # Represent the group by its shortest label, which is the primary
        # output when a package also ships '-dev', '-man' and friends.
        labels = {path: store_path_label(path) for path in output_paths}
        output_path = min(
            output_paths, key=lambda path: (len(labels[path]), labels[path])
        )
        label = labels[output_path]
        match = (
            None
            if is_non_package_artifact_name(label)
            else _VERSIONED_NAME_RE.fullmatch(label)
        )
        if match is None:
            LOG.debug(
                "Skipping runtime outputs without package metadata: %s", output_paths
            )
            continue
        pname, version = match.group("pname", "version")
        rows.append(
            {
                cols.STORE_PATH: output_path,
                cols.NAME: f"{pname}-{version}",
                cols.PNAME: pname,
                cols.VERSION: version,
                cols.PATCH_PATHS: [],
                cols.PATCHES: "",
                "system": "",
                "out": output_path,
                cols.OUTPUTS: output_paths,
                cols.CPE: cpe_generator.generate(pname, version),
                "purl": nix_purl(pname, version),
                "urls": "",
                cols.METADATA_UNAVAILABLE: True,
            }
        )
    return rows


def _drop_alias_rows(rows, df_derivations):
    """Drop inferred rows that only name the major version of a known package.

    A store path such as '<hash>-dbus-1' is a compatibility alias for the real
    'dbus-1.16.2' component rather than a separate package, so it is dropped
    whenever the fuller version is already known.
    """
    # Only bare-integer versions can ever be dropped, so the known versions
    # worth collecting are the ones sharing a pname with such a row.
    alias_pnames = {row[cols.PNAME] for row in rows if row[cols.VERSION].isdigit()}
    if not alias_pnames:
        return rows
    known_versions = [
        (row[cols.PNAME], row[cols.VERSION])
        for row in rows
        if row[cols.PNAME] in alias_pnames
    ]
    if {cols.PNAME, cols.VERSION}.issubset(df_derivations.columns):
        df_known = df_derivations[df_derivations[cols.PNAME].isin(alias_pnames)]
        known_versions.extend(
            df_known[[cols.PNAME, cols.VERSION]].itertuples(index=False, name=None)
        )
    dotted_version_prefixes = {
        (pname, version.partition(".")[0])
        for pname, version in known_versions
        if "." in version
    }
    return [
        row
        for row in rows
        if not (
            row[cols.VERSION].isdigit()
            and (row[cols.PNAME], row[cols.VERSION]) in dotted_version_prefixes
        )
    ]


def _derivations_to_dataframe(derivations, cpe_generator):
    """Return component rows for loaded derivations."""
    drv_dicts = []
    for drv in derivations:
        drv.set_cpe(cpe_generator)
        drv_dicts.append(drv.to_dict())
    return pd.DataFrame.from_records(drv_dicts)


def filter_runtime_outputs_by_load_path(paths, output_paths_by_load_path):
    """Filter runtime output mappings to the selected component paths."""
    selected_paths = set(paths)
    filtered_outputs_by_load_path = {}
    for load_path, output_paths in output_paths_by_load_path.items():
        filtered_output_paths = set(output_paths) & selected_paths
        if filtered_output_paths:
            filtered_outputs_by_load_path[load_path] = filtered_output_paths
    return filtered_outputs_by_load_path
