#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""SARIF 2.1.0 serialization for normalized vulnxscan findings."""

import json
import math
import pathlib
import re
from urllib.parse import quote

import pandas as pd

from common import columns as cols
from common.log import LOG
from common.pkgmeta import get_py_pkg_version
from common.versioning import parse_version
from vulnxscan.evidence import finding_id

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/tiiuae/sbomnix"
_SCANNERS = ("grype", "osv", "vulnix")
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,19}", re.IGNORECASE)


def findings_to_sarif(  # noqa: PLR0912, PLR0914, PLR0915
    findings,
    *,
    evidence_document=None,
    triage_findings=None,
    tool_version=None,
    location=None,
):
    """Return SARIF for final normalized, filtered finding rows."""
    findings = findings if findings is not None else pd.DataFrame()
    records = sorted(
        findings.to_dict("records"),
        key=lambda row: (
            _text(row.get(cols.VULN_ID)),
            _text(row.get(cols.PACKAGE)),
            _version(row),
        ),
    )
    evidence_document = evidence_document or {}
    observation_metadata, descriptions = _scanner_metadata(
        evidence_document.get("observations", [])
    )
    nixpkgs_prs = _nixpkgs_prs_by_finding(triage_findings)
    evidence_findings = {
        item.get(cols.FINDING_ID): item
        for item in evidence_document.get("findings", [])
    }
    evidence_components = {}
    for component in evidence_document.get("components", []):
        evidence_components.setdefault(component.get(cols.FINDING_ID), []).append(
            component
        )

    rule_metadata = _rule_metadata(records, nixpkgs_prs)
    rule_ids = sorted(rule_metadata)
    rule_indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    rules = [
        _sarif_rule(rule_id, rule_metadata[rule_id], descriptions)
        for rule_id in rule_ids
    ]

    results = []
    for row in records:
        vuln_id = _text(row.get(cols.VULN_ID))
        package = _text(row.get(cols.PACKAGE))
        version = _version(row)
        severity = _text(row.get(cols.SEVERITY))
        fid = row.get(cols.FINDING_ID)
        evidence = evidence_findings.get(fid, {})
        sources = sorted(evidence.get("scanners", [])) or sorted(
            scanner for scanner in _SCANNERS if _is_true(row.get(scanner))
        )
        properties: dict[str, object] = {"package": package, "version": version}
        if severity:
            properties["severity"] = severity
        score = _numeric_severity(severity)
        if score is not None:
            properties["cvssScore"] = score
        if sources:
            properties["sources"] = sources
        for column, name in (
            (cols.EVIDENCE_SCOPE, "evidenceScope"),
            (cols.PATCH_STATE, "patchState"),
        ):
            value = _text(row.get(column))
            if value:
                properties[name] = value
        components = evidence_components.get(fid, [])
        drv_paths = sorted(
            {
                _text(component.get(cols.DRV_PATH))
                for component in components
                if _text(component.get(cols.DRV_PATH))
            }
        )
        store_paths = sorted(
            {
                _text(path)
                for component in components
                for path in component.get("output_paths", [])
                if _text(path)
            }
        )
        if drv_paths:
            properties["drvPaths"] = drv_paths
        if store_paths:
            properties["storePaths"] = store_paths
        metadata = observation_metadata.get(
            (vuln_id, package, version),
            {"fix_states": set(), "fix_versions": set()},
        )
        fix_states = sorted(metadata["fix_states"])
        fix_versions = sorted(metadata["fix_versions"], key=_version_sort_key)
        for values, name in (
            (fix_states, "fixStates"),
            (fix_versions, "fixVersions"),
        ):
            if values:
                properties[name] = values
        finding_prs = nixpkgs_prs.get((vuln_id, package, version), [])

        fingerprint = _fingerprint(vuln_id, package, version)
        result = {
            "ruleId": vuln_id,
            "ruleIndex": rule_indexes[vuln_id],
            "level": _sarif_level(severity),
            "message": {
                "text": _result_message(
                    vuln_id,
                    package,
                    version,
                    properties,
                    drv_paths=drv_paths,
                )
            },
            # GitHub currently consumes only primaryLocationLineHash. The
            # versioned key retains the producer-defined identity for other
            # consumers. Both intentionally exclude Nix hashes.
            "partialFingerprints": {
                "primaryLocationLineHash": fingerprint,
                "vulnxscan/v1": fingerprint,
            },
            "properties": properties,
        }
        if finding_prs:
            result["workItemUris"] = finding_prs
        if location is not None:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": quote(str(location), safe="/")}
                    }
                }
            ]
        results.append(result)

    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnxscan",
                        "informationUri": _INFORMATION_URI,
                        "version": tool_version or get_py_pkg_version(),
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(document, path):
    """Atomically write a SARIF document."""
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


def _fingerprint(vuln_id, package, version):
    """Identify a versioned vulnerability/package across rebuild changes."""
    return finding_id(vuln_id, package, version).removeprefix("sha256:")


def _scanner_metadata(observations):
    metadata_by_finding = {}
    descriptions = {}
    for observation in observations:
        key = (
            _text(observation.get(cols.VULN_ID)),
            _text(observation.get(cols.PACKAGE)),
            _text(observation.get(cols.VERSION)),
        )
        metadata = metadata_by_finding.setdefault(
            key, {"fix_states": set(), "fix_versions": set()}
        )
        description = _text(observation.get(cols.DESCRIPTION))
        if description:
            descriptions.setdefault(key[0], set()).add(description)
        fix_state = _text(observation.get(cols.FIX_STATE))
        if fix_state:
            metadata["fix_states"].add(fix_state)
        for fix_version in _text(observation.get(cols.FIX_VERSIONS)).split(","):
            if fix_version.strip():
                metadata["fix_versions"].add(fix_version.strip())
    return metadata_by_finding, descriptions


def _rule_metadata(records, nixpkgs_prs):
    metadata = {}
    for row in records:
        rule_id = _text(row.get(cols.VULN_ID))
        rule = metadata.setdefault(
            rule_id, {"url": "", "scores": set(), "nixpkgs_prs": set()}
        )
        url = _text(row.get(cols.URL))
        if not rule["url"] and url:
            rule["url"] = url
        score = _numeric_severity(_text(row.get(cols.SEVERITY)))
        if score is not None and score > 0:
            rule["scores"].add(score)
        package = _text(row.get(cols.PACKAGE))
        version = _version(row)
        for pr_url in nixpkgs_prs.get((rule_id, package, version), []):
            rule["nixpkgs_prs"].add((package, version, pr_url))
    return metadata


def _sarif_rule(rule_id, metadata, descriptions):
    properties: dict[str, object] = {"tags": ["security", "vulnerability"]}
    scores = metadata["scores"]
    if scores:
        properties["security-severity"] = f"{max(scores):g}"
    rule = {
        "id": rule_id,
        "shortDescription": {"text": rule_id},
        "properties": properties,
    }
    description = f"Vulnerability {rule_id}."
    rule_descriptions = descriptions.get(rule_id, set())
    if rule_descriptions:
        description = max(rule_descriptions, key=lambda value: (len(value), value))
        description = _truncate(description, 1024)
    rule["fullDescription"] = {"text": description}
    links = _rule_links(rule_id, metadata["url"])
    links.extend(
        (
            f"Nixpkgs PR for {' '.join(value for value in (package, version) if value)}",
            url,
        )
        for package, version, url in sorted(metadata["nixpkgs_prs"])
    )
    if links:
        help_text = "\n".join(f"{label}: {url}" for label, url in links)
        help_markdown = " | ".join(
            f"[{_markdown_label(label)}]({url})" for label, url in links
        )
        if rule_descriptions:
            # GitHub renders help markdown on the alert page, so include
            # scanner descriptions there instead of relying on metadata alone.
            help_text = f"{help_text}\n\n{description}"
            help_markdown = f"{help_markdown}\n\n{description}"
        rule["helpUri"] = links[0][1]
    else:
        help_text = help_markdown = description
    rule["help"] = {"text": help_text, "markdown": help_markdown}
    return rule


def _result_message(
    vuln_id,
    package,
    version,
    properties,
    *,
    drv_paths,
):
    """Build visible GitHub alert context from available scanner evidence."""
    affected = " ".join(value for value in (package, version) if value)
    parts = [f"{vuln_id} affects {affected}."]
    severity = properties.get("severity")
    if severity:
        parts.append(f"Severity: {severity}.")
    sources = properties.get("sources", [])
    if sources:
        parts.append(f"Detected by: {', '.join(sources)}.")
    fix_versions = properties.get("fixVersions", [])
    fix_states = properties.get("fixStates", [])
    if fix_versions:
        parts.append(f"Fixed versions reported by scanners: {', '.join(fix_versions)}.")
    if fix_states:
        parts.append(f"Scanner fix state: {', '.join(fix_states)}.")
    patch_state = properties.get("patchState")
    if patch_state:
        parts.append(f"Nix patch evidence: {patch_state}.")
    if drv_paths:
        parts.append(f"Derivations: {', '.join(drv_paths)}.")
    return " ".join(parts)


def _truncate(value, limit):
    if len(value) <= limit:
        return value
    return f"{value[: limit - 3]}..."


def _version_sort_key(value):
    parsed = parse_version(value)
    return parsed is None, parsed, value


def _rule_links(rule_id, existing_url):
    if _CVE_ID_RE.fullmatch(rule_id):
        cve_id = rule_id.upper()
        return [
            (
                "NVD record",
                existing_url or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            ),
            (
                "Nixpkgs Security Tracker",
                f"https://tracker.security.nixos.org/suggestions/by-cve/{cve_id}/",
            ),
        ]
    encoded_id = quote(rule_id, safe="")
    if rule_id.casefold().startswith("ghsa-"):
        links = [("GitHub Advisory", f"https://github.com/advisories/{encoded_id}")]
        links.append(
            (
                "OSV record",
                existing_url or f"https://osv.dev/vulnerability/{encoded_id}",
            )
        )
        return links
    return [("Vulnerability record", existing_url)] if existing_url else []


def _nixpkgs_prs_by_finding(triage_findings):
    if triage_findings is None or cols.NIXPKGS_PR not in triage_findings:
        return {}
    result = {}
    for row in triage_findings.to_dict("records"):
        urls = _text(row.get(cols.NIXPKGS_PR)).split()
        if not urls:
            continue
        key = (
            _text(row.get(cols.VULN_ID)),
            _text(row.get(cols.PACKAGE)),
            _version(row),
        )
        result.setdefault(key, set()).update(urls)
    return {key: sorted(urls) for key, urls in result.items()}


def _markdown_label(value):
    return value.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def _sarif_level(severity):
    normalized = severity.strip().casefold()
    named_levels = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "moderate": "warning",
        "low": "note",
        "none": "note",
    }
    if normalized in named_levels:
        return named_levels[normalized]
    score = _numeric_severity(severity)
    if score is None:
        return "warning"
    return "error" if score >= 7 else "warning" if score >= 4 else "note"


def _numeric_severity(severity):
    try:
        score = float(severity)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score) or not 0 <= score <= 10:
        return None
    return score


def _version(row):
    return _text(row.get(cols.VERSION_LOCAL) or row.get(cols.VERSION))


def _text(value):
    if value is None or pd.isna(value):
        return ""
    return str(value)


def _is_true(value):
    return value is True or _text(value).strip().casefold() in {"1", "true"}
