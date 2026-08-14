#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Component evidence helpers for vulnxscan reports."""

import ast
import hashlib
import json
import math
import pathlib
import re
from dataclasses import dataclass
from types import SimpleNamespace
from typing import cast

import pandas as pd

from common import columns as cols
from common.df import df_from_csv_file
from common.log import LOG
from vulnxscan.utils import _vuln_sortcol, _vuln_url

STATE_MATCH = "vuln_id_patch_name_match"
STATE_NO_MATCH = "no_vuln_id_patch_name_match"
STATE_METADATA_UNAVAILABLE = "metadata_unavailable"
STATE_PACKAGE_VERSION_ONLY = "package_version_only"
COMPONENT_STATES = frozenset(
    {
        STATE_MATCH,
        STATE_NO_MATCH,
        STATE_METADATA_UNAVAILABLE,
        STATE_PACKAGE_VERSION_ONLY,
    }
)

PATCH_STATE_ALL_MATCH = "all_components_match"
PATCH_STATE_MIXED = "mixed_component_evidence"
PATCH_STATE_NO_MATCH = "no_component_match"
PATCH_STATE_METADATA_UNAVAILABLE = "metadata_unavailable"
PATCH_STATE_PACKAGE_VERSION_ONLY = "package_version_only"

SCOPE_EXACT = "component_exact"
SCOPE_EXPANDED = "component_expanded"
SCOPE_MIXED = "component_mixed"
SCOPE_PACKAGE_VERSION_ONLY = "package_version_only"

RESOLUTION_EXACT = "exact"
RESOLUTION_EXPANDED = "expanded"
RESOLUTION_UNRESOLVED = "unresolved"
RESOLUTIONS = frozenset(
    {
        RESOLUTION_EXACT,
        RESOLUTION_EXPANDED,
        RESOLUTION_UNRESOLVED,
    }
)

IDENTITY_SCANNER_COMPONENT_REF = "scanner_component_ref"
IDENTITY_SBOM_PACKAGE_VERSION_JOIN = "sbom_package_version_join"
IDENTITY_UNRESOLVED = "unresolved"

EVIDENCE_COUNT_COLUMNS = [
    cols.RESOLVED_COMPONENT_COUNT,
    cols.VULN_ID_PATCH_NAME_MATCH_COUNT,
    cols.NO_VULN_ID_PATCH_NAME_MATCH_COUNT,
    cols.METADATA_UNAVAILABLE_COUNT,
    cols.PACKAGE_VERSION_ONLY_COUNT,
]

EVIDENCE_REPORT_COLUMNS = [
    cols.FINDING_ID,
    cols.EVIDENCE_SCOPE,
    cols.PATCH_STATE,
    *EVIDENCE_COUNT_COLUMNS,
]

_BASE_OBSERVATION_COLUMNS = [
    cols.VULN_ID,
    cols.PACKAGE,
    cols.VERSION,
    cols.SEVERITY,
    cols.SCANNER,
    cols.COMPONENT_REF,
    cols.MODIFIED,
    cols.DESCRIPTION,
    cols.FIX_STATE,
    cols.FIX_VERSIONS,
]

_REPORT_SORT_COLUMNS = [cols.SORTCOL, cols.PACKAGE, cols.SEVERITY, cols.VERSION]

_SEVERITY_VALUES = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "moderate": 5.5,
    "low": 2.0,
    "none": 0.0,
    "unknown": 0.0,
    "": 0.0,
}


@dataclass(frozen=True)
class Component:
    """Normalized SBOM component used for evidence resolution."""

    component_id: str
    pname: str
    version: str
    drv_path: str
    output_paths: tuple[str, ...]
    patch_paths: tuple[str, ...]
    metadata_unavailable: bool = False


@dataclass(frozen=True)
class ComponentIndex:
    """Lookup indexes for normalized SBOM components."""

    by_id: dict[str, Component]
    by_package_version: dict[tuple[str, str], list[Component]]


@dataclass(frozen=True)
class EvidenceReport:
    """Aggregate report dataframe and matching evidence document."""

    report: pd.DataFrame
    document: dict
    observations: pd.DataFrame


def finding_id(vuln_id, package, version):
    """Return the stable finding identifier for a vulnerability tuple."""
    payload = json.dumps(
        [str(vuln_id), str(package), str(version)],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def empty_evidence_document():
    """Return an empty schema v1 evidence document."""
    return {
        "schema_version": 1,
        "observations": [],
        "findings": [],
        "components": [],
    }


def normalize_scanner_observations(scanner_frames):
    """Return deduplicated scanner observations in a common shape."""
    frames = [df for df in scanner_frames if df is not None]
    if not frames:
        return pd.DataFrame(columns=_BASE_OBSERVATION_COLUMNS + [cols.SORTCOL])
    df = pd.concat(frames, ignore_index=True)
    if df.empty:
        return pd.DataFrame(columns=_BASE_OBSERVATION_COLUMNS + [cols.SORTCOL])
    df = df.copy(deep=True)
    for column in _BASE_OBSERVATION_COLUMNS:
        if column not in df.columns:
            df[column] = ""
    df.fillna("", inplace=True)
    for column in _BASE_OBSERVATION_COLUMNS:
        if column != cols.MODIFIED:
            df[column] = df[column].astype(str)
    df[cols.SORTCOL] = df.apply(_vuln_sortcol, axis=1)
    df = df[_BASE_OBSERVATION_COLUMNS + [cols.SORTCOL]]
    df.drop_duplicates(
        subset=[
            cols.VULN_ID,
            cols.PACKAGE,
            cols.VERSION,
            cols.SEVERITY,
            cols.SCANNER,
            cols.COMPONENT_REF,
        ],
        keep="first",
        inplace=True,
    )
    df.reset_index(drop=True, inplace=True)
    return df


def build_evidence_report(
    scanner_frames,
    *,
    scanner_columns,
    sbom_csv=None,
    log=LOG,
):
    """Return active aggregate report rows and full component evidence."""
    observations = normalize_scanner_observations(scanner_frames)
    if observations.empty:
        return EvidenceReport(
            report=_empty_report_dataframe(scanner_columns),
            document=empty_evidence_document(),
            observations=observations,
        )
    components = load_component_index(sbom_csv, log=log) if sbom_csv else None
    rows = []
    finding_docs = []
    component_docs = []
    observation_docs = []
    group_cols = [cols.VULN_ID, cols.PACKAGE, cols.VERSION]
    for group_key, df_finding in observations.groupby(group_cols, sort=True):
        # Grouping by three columns always yields a 3-tuple key, but the
        # pandas stubs only promise Hashable.
        vuln_id, package, version = cast(tuple[str, str, str], group_key)
        finding_key = (str(vuln_id), str(package), str(version))
        built = _build_finding(finding_key, df_finding, components, scanner_columns)
        finding_docs.append(built["finding"])
        component_docs.extend(built["components"])
        observation_docs.extend(built["observations"])
        if built["finding"][cols.SUPPRESSED_BY_PATCH_EVIDENCE]:
            _log_patch_suppression(built, log)
            continue
        rows.append(built["report_row"])
    report = pd.DataFrame(rows, columns=_report_columns(scanner_columns))
    report.sort_values(by=_REPORT_SORT_COLUMNS, ascending=False, inplace=True)
    document = {
        "schema_version": 1,
        "observations": _finalize_observations(observation_docs),
        "findings": sorted(
            finding_docs,
            key=lambda item: (
                item[cols.VULN_ID],
                item[cols.PACKAGE],
                item[cols.VERSION],
            ),
        ),
        "components": sorted(
            component_docs,
            key=lambda item: (
                item[cols.FINDING_ID],
                item["component_id"],
                ",".join(item["identity_sources"]),
            ),
        ),
    }
    validate_evidence_document(document)
    return EvidenceReport(report=report, document=document, observations=observations)


def _log_patch_suppression(built, log):
    """Announce a finding dropped from the report because every component
    carries a patch naming the vulnerability."""
    finding = built["finding"]
    patches = sorted(
        {
            patch
            for component in built["components"]
            for patch in component["matching_patch_paths"]
        }
    )
    log.info(
        "%s for '%s' is patched with: %s",
        finding[cols.VULN_ID],
        finding[cols.PACKAGE],
        patches,
    )


def load_component_index(sbom_csv, *, log=LOG):
    """Load and normalize SBOM CSV components for evidence resolution."""
    df = df_from_csv_file(sbom_csv)
    components = {}
    has_output_json = cols.OUTPUT_PATHS_JSON in df.columns
    has_patch_json = cols.PATCH_PATHS_JSON in df.columns
    for row in df.to_dict("records"):
        component = _component_from_row(row, has_output_json, has_patch_json)
        if not component.component_id:
            continue
        existing = components.get(component.component_id)
        if existing is None:
            components[component.component_id] = component
        else:
            components[component.component_id] = _merge_components(existing, component)
    by_package_version = {}
    for component in components.values():
        key = (component.pname, component.version)
        by_package_version.setdefault(key, []).append(component)
    for matches in by_package_version.values():
        matches.sort(key=lambda component: component.component_id)
    log.debug("Loaded %d component evidence record(s)", len(components))
    return ComponentIndex(
        by_id=dict(sorted(components.items())),
        by_package_version=by_package_version,
    )


def write_evidence_document(document, path):
    """Validate and atomically write an evidence document."""
    validate_evidence_document(document)
    out_path = pathlib.Path(path)
    tmp_path = out_path.with_name(f".{out_path.name}.tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as outfile:
            json.dump(document, outfile, indent=2, ensure_ascii=False)
            outfile.write("\n")
        tmp_path.replace(out_path)
    finally:
        tmp_path.unlink(missing_ok=True)
    LOG.info("Wrote: %s", out_path)


def validate_evidence_document(document):
    """Raise AssertionError if the evidence document is internally inconsistent."""
    if document.get("schema_version") != 1:
        raise AssertionError("Unsupported evidence schema")
    findings = document.get("findings", [])
    observations = document.get("observations", [])
    components = document.get("components", [])
    finding_ids = {finding[cols.FINDING_ID] for finding in findings}
    if len(finding_ids) != len(findings):
        raise AssertionError("Duplicate finding_id")
    observation_ids = {
        observation["observation_id"]
        for observation in observations
        if "observation_id" in observation
    }
    if len(observation_ids) != len(observations):
        raise AssertionError("Duplicate observation_id")
    vuln_ids = {finding[cols.FINDING_ID]: finding[cols.VULN_ID] for finding in findings}
    _validate_component_entries(components, vuln_ids)
    resolutions = _validate_observations(observations, finding_ids)
    for finding in findings:
        expected_id = finding_id(
            finding[cols.VULN_ID],
            finding[cols.PACKAGE],
            finding[cols.VERSION],
        )
        if finding[cols.FINDING_ID] != expected_id:
            raise AssertionError("Invalid finding_id")
        _validate_finding_scope(finding, resolutions.get(finding[cols.FINDING_ID]))
        _validate_finding_counts(finding, components)
    for component in components:
        if component[cols.FINDING_ID] not in finding_ids:
            raise AssertionError("Component references missing finding")
    if _contains_none(document):
        raise AssertionError("Evidence document must not contain null values")


def _validate_observations(observations, finding_ids):
    """Validate observations and return the resolutions seen per finding.

    Observations are what `evidence_scope` is derived from, so each one is
    checked against the finding it claims to belong to rather than taken at
    face value.
    """
    resolutions = {}
    for observation in observations:
        fid = observation[cols.FINDING_ID]
        if fid not in finding_ids:
            raise AssertionError("Observation references missing finding")
        if observation["resolution"] not in RESOLUTIONS:
            raise AssertionError("Invalid observation resolution")
        expected_id = finding_id(
            observation[cols.VULN_ID],
            observation[cols.PACKAGE],
            observation[cols.VERSION],
        )
        if fid != expected_id:
            raise AssertionError("Observation disagrees with its finding")
        resolutions.setdefault(fid, set()).add(observation["resolution"])
    return resolutions


def _validate_finding_scope(finding, resolutions):
    """Require `evidence_scope` to match the observations behind the finding.

    Recomputed rather than range-checked: an in-range but wrong scope would
    otherwise claim, say, an exact component match for a finding whose every
    observation went unresolved.
    """
    if not resolutions:
        raise AssertionError("Finding has no observations")
    if finding[cols.EVIDENCE_SCOPE] != _evidence_scope(resolutions):
        raise AssertionError("Invalid evidence scope")


def _validate_component_entries(components, vuln_ids):
    seen = set()
    allowed_identity_sources = {
        IDENTITY_SCANNER_COMPONENT_REF,
        IDENTITY_SBOM_PACKAGE_VERSION_JOIN,
        IDENTITY_UNRESOLVED,
    }
    for component in components:
        key = (component[cols.FINDING_ID], component["component_id"])
        if key in seen:
            raise AssertionError("Duplicate component evidence")
        seen.add(key)
        identity_sources = component["identity_sources"]
        if not set(identity_sources).issubset(allowed_identity_sources):
            raise AssertionError("Invalid component identity source")
        # Reject unknown states before the counts are reconciled. An unknown
        # state counts as resolved but lands in no evidence category, so the
        # totals would silently stop adding up.
        if component["patch_evidence_state"] not in COMPONENT_STATES:
            raise AssertionError("Invalid component patch evidence state")
        component_suppressed = component["patch_evidence_state"] == STATE_MATCH
        if component[cols.SUPPRESSED_BY_PATCH_EVIDENCE] is not component_suppressed:
            raise AssertionError("Invalid component suppression state")
        vuln_id = vuln_ids.get(component[cols.FINDING_ID])
        if vuln_id is not None:
            # Components of an unknown finding are rejected further down.
            _validate_component_patch_evidence(component, vuln_id)


def _validate_component_patch_evidence(component, vuln_id):
    """Require a component's recorded state to agree with its own patch paths.

    Every suppression rests on `patch_evidence_state`, so it is recomputed from
    the serialized paths rather than trusted, the same way the aggregate counts
    are. Without this, a component claiming a match while carrying no patch
    that names the vulnerability would validate, and the finding built on it
    would stay suppressed.
    """
    state = component["patch_evidence_state"]
    matching = component["matching_patch_paths"]
    expected = _matching_patch_paths(component[cols.PATCHES], vuln_id)
    if state == STATE_MATCH:
        if not matching or matching != expected:
            raise AssertionError("Component patch match disagrees with its patches")
        return
    if matching:
        raise AssertionError("Unmatched component reports a matching patch")
    if state == STATE_NO_MATCH and expected:
        raise AssertionError("Component ignores a patch naming the vulnerability")
    # STATE_METADATA_UNAVAILABLE asserts nothing further: the reason the
    # metadata was unusable is not serialized, and the patch list may be
    # populated even when the output paths were not readable.
    if state == STATE_PACKAGE_VERSION_ONLY and component[cols.PATCHES]:
        raise AssertionError("Unresolved component reports patches")


def _report_columns(scanner_columns):
    return (
        [cols.VULN_ID, cols.URL, cols.PACKAGE, cols.VERSION, cols.SEVERITY]
        + list(scanner_columns)
        + [cols.SUM, cols.SORTCOL]
        + EVIDENCE_REPORT_COLUMNS
    )


def _empty_report_dataframe(scanner_columns):
    return pd.DataFrame(columns=_report_columns(scanner_columns))


def _component_from_row(row, has_output_json, has_patch_json):
    component_id = _as_str(row.get(cols.STORE_PATH))
    pname = _as_str(row.get(cols.PNAME))
    version = _as_str(row.get(cols.VERSION))
    outputs, output_error = _output_paths_from_row(row, has_output_json)
    patches, patch_error = _patch_paths_from_row(row, has_patch_json)
    metadata_unavailable = (
        _as_str(row.get(cols.METADATA_UNAVAILABLE)).casefold() == "true"
    )
    return Component(
        component_id=component_id,
        pname=pname,
        version=version,
        drv_path=component_id,
        output_paths=tuple(sorted(dict.fromkeys(outputs))),
        patch_paths=tuple(sorted(dict.fromkeys(patches))),
        metadata_unavailable=metadata_unavailable or output_error or patch_error,
    )


def _output_paths_from_row(row, has_output_json):
    if has_output_json:
        return _json_string_list(row.get(cols.OUTPUT_PATHS_JSON))
    return _legacy_output_paths(row.get(cols.OUTPUTS)), False


def _patch_paths_from_row(row, has_patch_json):
    if has_patch_json:
        return _json_string_list(row.get(cols.PATCH_PATHS_JSON))
    patches = _as_str(row.get(cols.PATCHES))
    if not patches:
        return [], False
    return patches.split(), False


def _json_string_list(value):
    try:
        decoded = json.loads(_as_str(value))
    except json.JSONDecodeError:
        return [], True
    if not isinstance(decoded, list):
        return [], True
    if any(not isinstance(item, str) for item in decoded):
        return [], True
    return [item for item in decoded if item], False


def _legacy_output_paths(value):
    text = _as_str(value)
    if not text:
        return []
    try:
        decoded = ast.literal_eval(text)
    except (SyntaxError, ValueError):
        return [text]
    if isinstance(decoded, (list, tuple, set)):
        return [str(item) for item in decoded if str(item)]
    if isinstance(decoded, str) and decoded:
        return [decoded]
    return []


def _merge_components(left, right):
    unavailable = left.metadata_unavailable or right.metadata_unavailable
    if (
        left.pname != right.pname
        or left.version != right.version
        or left.drv_path != right.drv_path
    ):
        unavailable = True
    if left.patch_paths != right.patch_paths:
        unavailable = True
    return Component(
        component_id=left.component_id,
        pname=left.pname,
        version=left.version,
        drv_path=left.drv_path,
        output_paths=tuple(sorted({*left.output_paths, *right.output_paths})),
        patch_paths=tuple(sorted({*left.patch_paths, *right.patch_paths})),
        metadata_unavailable=unavailable,
    )


def _build_finding(finding_key, df_finding, components, scanner_columns):
    vuln_id, package, version = finding_key
    fid = finding_id(vuln_id, package, version)
    resolved = _resolve_finding(finding_key, fid, df_finding, components)
    component_docs = resolved["components"]
    counts = _component_counts(component_docs)
    patch_state = _aggregate_patch_state(counts, resolved["has_unresolved"])
    suppressed = patch_state == PATCH_STATE_ALL_MATCH
    for component in component_docs:
        component[cols.SUPPRESSED_BY_PATCH_EVIDENCE] = (
            component["patch_evidence_state"] == STATE_MATCH
        )
    selected = _select_severity_observation(df_finding)
    scanners = sorted(set(df_finding[cols.SCANNER].astype(str)))
    finding = _finding_document(
        {
            "fid": fid,
            "finding_key": finding_key,
            "resolutions": resolved["resolutions"],
            "patch_state": patch_state,
            "counts": counts,
            "suppressed": suppressed,
        },
        selected,
        scanners,
    )
    report_row = _report_row(finding, scanner_columns)
    return {
        "finding": finding,
        "components": component_docs,
        "observations": resolved["observations"],
        "report_row": report_row,
    }


def _resolve_finding(finding_key, fid, df_finding, components):
    vuln_id, package, version = finding_key
    resolved = {}
    observation_docs = []
    has_unresolved = False
    resolutions = set()
    for observation in df_finding.to_dict("records"):
        matches, resolution = _resolve_observation(observation, components)
        resolutions.add(resolution)
        if resolution == RESOLUTION_UNRESOLVED:
            has_unresolved = True
        for component in matches:
            entry = resolved.setdefault(
                component.component_id,
                {"component": component, "identity_sources": set()},
            )
            entry["identity_sources"].add(_identity_source_for_resolution(resolution))
        observation_docs.append(
            {
                cols.FINDING_ID: fid,
                cols.SCANNER: _as_str(observation.get(cols.SCANNER)),
                cols.VULN_ID: vuln_id,
                cols.PACKAGE: package,
                cols.VERSION: version,
                cols.SEVERITY: _as_str(observation.get(cols.SEVERITY)),
                cols.COMPONENT_REF: _as_str(observation.get(cols.COMPONENT_REF)),
                "resolution": resolution,
            }
        )
    return {
        "components": _component_docs(fid, vuln_id, resolved, has_unresolved),
        "observations": observation_docs,
        "resolutions": resolutions,
        "has_unresolved": has_unresolved,
    }


def _finding_document(state, selected, scanners):
    fid = state["fid"]
    finding_key = state["finding_key"]
    vuln_id, package, version = finding_key
    return {
        cols.FINDING_ID: fid,
        cols.VULN_ID: vuln_id,
        cols.PACKAGE: package,
        cols.VERSION: version,
        cols.SEVERITY: _as_str(selected[cols.SEVERITY]),
        "scanners": scanners,
        cols.URL: _url_for(vuln_id, scanners),
        cols.SORTCOL: _as_str(selected[cols.SORTCOL]),
        cols.EVIDENCE_SCOPE: _evidence_scope(state["resolutions"]),
        cols.PATCH_STATE: state["patch_state"],
        **state["counts"],
        cols.SUPPRESSED_BY_PATCH_EVIDENCE: state["suppressed"],
    }


def _report_row(finding, scanner_columns):
    scanners = finding["scanners"]
    report_row = {
        cols.VULN_ID: finding[cols.VULN_ID],
        cols.URL: finding[cols.URL],
        cols.PACKAGE: finding[cols.PACKAGE],
        cols.VERSION: finding[cols.VERSION],
        cols.SEVERITY: finding[cols.SEVERITY],
        cols.SUM: len(scanners),
        cols.SORTCOL: finding[cols.SORTCOL],
        cols.FINDING_ID: finding[cols.FINDING_ID],
        cols.EVIDENCE_SCOPE: finding[cols.EVIDENCE_SCOPE],
        cols.PATCH_STATE: finding[cols.PATCH_STATE],
    }
    for column in EVIDENCE_COUNT_COLUMNS:
        report_row[column] = finding[column]
    for scanner in scanner_columns:
        report_row[scanner] = "1" if scanner in scanners else "0"
    return report_row


def _resolve_observation(observation, components):
    if components is None:
        return [], RESOLUTION_UNRESOLVED
    component_ref = _as_str(observation.get(cols.COMPONENT_REF))
    if component_ref:
        component = components.by_id.get(component_ref)
        if component:
            return [component], RESOLUTION_EXACT
    key = (
        _as_str(observation.get(cols.PACKAGE)),
        _as_str(observation.get(cols.VERSION)),
    )
    matches = components.by_package_version.get(key, [])
    if matches:
        return matches, RESOLUTION_EXPANDED
    return [], RESOLUTION_UNRESOLVED


def _component_docs(fid, vuln_id, resolved, has_unresolved):
    docs = []
    for component_id, entry in sorted(resolved.items()):
        component = entry["component"]
        state, matching_patches = _component_patch_state(component, vuln_id)
        docs.append(
            {
                cols.FINDING_ID: fid,
                "component_id": component_id,
                "identity_sources": sorted(entry["identity_sources"]),
                cols.DRV_PATH: component.drv_path,
                "output_paths": list(component.output_paths),
                cols.PNAME: component.pname,
                cols.VERSION: component.version,
                cols.PATCHES: list(component.patch_paths),
                "patch_evidence_state": state,
                "matching_patch_paths": matching_patches,
                cols.SUPPRESSED_BY_PATCH_EVIDENCE: False,
            }
        )
    if has_unresolved:
        docs.append(
            {
                cols.FINDING_ID: fid,
                "component_id": "",
                "identity_sources": [IDENTITY_UNRESOLVED],
                cols.DRV_PATH: "",
                "output_paths": [],
                cols.PNAME: "",
                cols.VERSION: "",
                cols.PATCHES: [],
                "patch_evidence_state": STATE_PACKAGE_VERSION_ONLY,
                "matching_patch_paths": [],
                cols.SUPPRESSED_BY_PATCH_EVIDENCE: False,
            }
        )
    return docs


def _identity_source_for_resolution(resolution):
    if resolution == RESOLUTION_EXACT:
        return IDENTITY_SCANNER_COMPONENT_REF
    if resolution == RESOLUTION_EXPANDED:
        return IDENTITY_SBOM_PACKAGE_VERSION_JOIN
    return IDENTITY_UNRESOLVED


def _matching_patch_paths(patch_paths, vuln_id):
    """Return the patch paths whose file name names `vuln_id`.

    Shared by construction and validation so a suppression can be rechecked
    against the paths it claims to rest on, rather than trusted.
    """
    token_re = re.compile(
        rf"(?<![A-Za-z0-9]){re.escape(str(vuln_id))}(?![A-Za-z0-9])",
        re.IGNORECASE,
    )
    # Match the file name only. A vulnerability ID in a parent directory says
    # nothing about what this patch changes, and accepting it would suppress a
    # finding on the strength of a directory name.
    return [
        patch for patch in patch_paths if token_re.search(pathlib.PurePath(patch).name)
    ]


def _component_patch_state(component, vuln_id):
    if component.metadata_unavailable:
        return STATE_METADATA_UNAVAILABLE, []
    matches = _matching_patch_paths(component.patch_paths, vuln_id)
    if matches:
        return STATE_MATCH, matches
    return STATE_NO_MATCH, []


def _component_counts(component_docs):
    match_count = 0
    no_match_count = 0
    unavailable_count = 0
    resolved_count = 0
    for component in component_docs:
        state = component["patch_evidence_state"]
        if state == STATE_PACKAGE_VERSION_ONLY:
            continue
        resolved_count += 1
        if state == STATE_MATCH:
            match_count += 1
        elif state == STATE_NO_MATCH:
            no_match_count += 1
        elif state == STATE_METADATA_UNAVAILABLE:
            unavailable_count += 1
    return {
        cols.RESOLVED_COMPONENT_COUNT: resolved_count,
        cols.VULN_ID_PATCH_NAME_MATCH_COUNT: match_count,
        cols.NO_VULN_ID_PATCH_NAME_MATCH_COUNT: no_match_count,
        cols.METADATA_UNAVAILABLE_COUNT: unavailable_count,
        cols.PACKAGE_VERSION_ONLY_COUNT: 1 if resolved_count == 0 else 0,
    }


def _aggregate_patch_state(counts, has_unresolved):
    resolved_count = counts[cols.RESOLVED_COMPONENT_COUNT]
    match_count = counts[cols.VULN_ID_PATCH_NAME_MATCH_COUNT]
    no_match_count = counts[cols.NO_VULN_ID_PATCH_NAME_MATCH_COUNT]
    unavailable_count = counts[cols.METADATA_UNAVAILABLE_COUNT]
    if resolved_count == 0:
        return PATCH_STATE_PACKAGE_VERSION_ONLY
    if match_count == resolved_count and not unavailable_count and not has_unresolved:
        return PATCH_STATE_ALL_MATCH
    if match_count and (no_match_count or unavailable_count or has_unresolved):
        return PATCH_STATE_MIXED
    if unavailable_count or has_unresolved:
        return PATCH_STATE_METADATA_UNAVAILABLE
    return PATCH_STATE_NO_MATCH


def _evidence_scope(resolutions):
    resolved = {
        resolution for resolution in resolutions if resolution != RESOLUTION_UNRESOLVED
    }
    if not resolved:
        return SCOPE_PACKAGE_VERSION_ONLY
    if resolved == {RESOLUTION_EXACT}:
        return SCOPE_EXACT
    if resolved == {RESOLUTION_EXPANDED}:
        return SCOPE_EXPANDED
    return SCOPE_MIXED


def _select_severity_observation(df_finding):
    ranked = df_finding.copy(deep=True)
    ranked["_severity_score"] = ranked[cols.SEVERITY].apply(_severity_score)
    ranked["_severity_norm"] = ranked[cols.SEVERITY].apply(
        lambda value: _as_str(value).strip().casefold()
    )
    ranked["_severity_text"] = ranked[cols.SEVERITY].apply(_as_str)
    ranked.sort_values(
        by=[
            "_severity_score",
            "_severity_norm",
            cols.SCANNER,
            "_severity_text",
            cols.COMPONENT_REF,
        ],
        ascending=[False, True, True, True, True],
        inplace=True,
    )
    return ranked.iloc[0]


def _severity_score(value):
    if value is None or pd.isna(value):
        return 0.0
    text = str(value).strip()
    try:
        numeric = float(text)
    except ValueError:
        numeric = None
    if numeric is not None and math.isfinite(numeric) and 0 <= numeric <= 10:
        return numeric
    return _SEVERITY_VALUES.get(text.casefold(), 0.0)


def _url_for(vuln_id, scanners):
    row = SimpleNamespace(
        vuln_id=vuln_id,
        scanner=scanners,
        osv="osv" in scanners,
    )
    return _vuln_url(row)


def _finalize_observations(observations):
    sorted_observations = sorted(
        observations,
        key=lambda item: (
            item[cols.VULN_ID],
            item[cols.PACKAGE],
            item[cols.VERSION],
            item[cols.SCANNER],
            item[cols.SEVERITY],
            item[cols.COMPONENT_REF],
        ),
    )
    for index, observation in enumerate(sorted_observations):
        observation["observation_id"] = f"observation:{index}"
    return sorted_observations


def _validate_finding_counts(finding, components):
    finding_components = [
        component
        for component in components
        if component[cols.FINDING_ID] == finding[cols.FINDING_ID]
    ]
    counts = _component_counts(finding_components)
    for column in EVIDENCE_COUNT_COLUMNS:
        if finding[column] != counts[column]:
            raise AssertionError(f"Invalid evidence count: {column}")
    has_unresolved = any(
        component["patch_evidence_state"] == STATE_PACKAGE_VERSION_ONLY
        for component in finding_components
    )
    patch_state = _aggregate_patch_state(counts, has_unresolved)
    if finding[cols.PATCH_STATE] != patch_state:
        raise AssertionError("Invalid aggregate patch state")
    suppressed = patch_state == PATCH_STATE_ALL_MATCH
    if finding[cols.SUPPRESSED_BY_PATCH_EVIDENCE] is not suppressed:
        raise AssertionError("Invalid aggregate suppression state")


def _contains_none(value):
    if value is None:
        return True
    if isinstance(value, dict):
        return any(_contains_none(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_none(item) for item in value)
    return False


def _as_str(value):
    if value is None or pd.isna(value):
        return ""
    return str(value)
