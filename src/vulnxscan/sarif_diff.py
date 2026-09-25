#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Compare vulnxscan SARIF documents and render a markdown diff.

The comparison understands the producer-defined semantics emitted by
vulnxscan.sarif: exact identity via the primaryLocationLineHash
fingerprint, version-independent grouping via the vulnxscan/package-v1
fingerprint, and detail comparison via result properties with Nix store
paths excluded.
"""

import argparse
import html
import itertools
import json
import pathlib
import re

from common.cli_args import add_verbose_argument, add_version_argument, check_positive
from common.errors import SbomnixError
from common.log import LOG, set_log_verbosity
from common.versioning import parse_version

_GROUP_FINGERPRINT_KEY = "vulnxscan/package-v1"

###############################################################################


def getargs(args=None):
    """Parse command line arguments"""
    desc = (
        "Render a markdown vulnerability diff between a current and an "
        "optional previous vulnxscan SARIF document."
    )
    epil = "Example: ./vulnxscan-diff.py --current vulns.sarif --markdown diff.md"
    parser = argparse.ArgumentParser(description=desc, epilog=epil)
    helps = "Path to the current SARIF file (json)."
    parser.add_argument("--current", help=helps, type=pathlib.Path, required=True)
    helps = (
        "Previous SARIF baseline. A missing file renders a no-baseline "
        "report, matching an empty cache restore on the first run."
    )
    parser.add_argument("--previous", help=helps, type=pathlib.Path)
    helps = "Path for the rendered markdown vulnerability diff."
    parser.add_argument("--markdown", help=helps, type=pathlib.Path, required=True)
    helps = (
        "Optional output size limit in characters. Excess entries are "
        "omitted with a note. Callers bound the diff for their medium, e.g. "
        "a GitHub comment cap."
    )
    parser.add_argument("--max-chars", help=helps, type=check_positive)
    add_verbose_argument(parser)
    add_version_argument(parser)
    return parser.parse_args(args)


def compare_sarif_files(current, markdown, previous=None, max_chars=None):
    """Render the vulnerability diff between two SARIF files."""
    markdown = pathlib.Path(markdown).resolve()
    markdown.parent.mkdir(parents=True, exist_ok=True)
    current_document = _load_json_file(pathlib.Path(current), "current SARIF")
    previous_document = None
    if previous is not None:
        previous = pathlib.Path(previous).resolve()
        if previous.is_file():
            previous_document = _load_json_file(previous, "previous SARIF")
        else:
            LOG.info("No previous SARIF baseline at %s", previous)
    try:
        report = render_sarif_diff(
            current_document, previous_document, max_chars=max_chars
        )
    except ValueError as error:
        raise SbomnixError(f"Could not compare SARIF: {error}") from error
    markdown.write_text(report, encoding="utf-8")
    LOG.info("Wrote: %s", markdown)


def render_sarif_diff(current_document, previous_document=None, *, max_chars=None):
    """Render a markdown diff between two SARIF documents.

    `max_chars` optionally bounds the output: trailing bullet entries are
    omitted with a note until the rendered text fits. Callers bound the diff
    for their medium; unbounded by default.
    """
    current = _keyed_sarif_results(current_document)
    if previous_document is None:
        detail = f"No previous SARIF baseline available ({len(current)} current)."
        return f"## Vulnerability Changes\n\n{detail}\n"

    previous = _keyed_sarif_results(previous_document)
    added, resolved, carried = _pair_sarif_results(current, previous)
    changed = [
        (previous[key], result)
        for key, result in current.items()
        if key in previous
        and _sarif_semantic_details(result, ignore_version=False)
        != _sarif_semantic_details(previous[key], ignore_version=False)
    ]
    # Carried pairs changed version by construction; only detail changes
    # beyond that (severity, scanners, fix state) are reported.
    carried_changed = [
        (before, after)
        for before, after in carried
        if _sarif_semantic_details(after, ignore_version=True)
        != _sarif_semantic_details(before, ignore_version=True)
    ]

    carried_note = (
        f"; {len(carried)} persisted across package version updates" if carried else ""
    )
    all_changed = changed + carried_changed
    if not (added or resolved or all_changed):
        detail = (
            "No finding additions, resolutions, or detail changes "
            f"({len(current)} current{carried_note})."
        )
        return f"## Vulnerability Changes\n\n{detail}\n"

    lines = [
        "## Vulnerability Changes",
        "",
        f"{len(current)} current, {len(added)} added, {len(resolved)} resolved, "
        f"{len(all_changed)} changed{carried_note}.",
    ]

    if added:
        lines.extend(("", "### Added", "", *(_format_finding(item) for item in added)))
    if resolved:
        lines.extend(
            ("", "### Resolved", "", *(_format_finding(item) for item in resolved))
        )
    if all_changed:
        lines.extend(("", "### Changed", ""))
        for before, after in all_changed:
            lines.append(
                f"- **{_safe_markdown_text(_sarif_rule_id(after))}**: "
                f"[{_safe_markdown_text(_sarif_level(before))}] "
                f"{_safe_markdown_text(_sarif_semantic_message(before))} => "
                f"[{_safe_markdown_text(_sarif_level(after))}] "
                f"{_safe_markdown_text(_sarif_semantic_message(after))}"
            )
    if max_chars is None:
        return "\n".join(lines).rstrip() + "\n"
    return _bound_sarif_diff(lines, max_chars)


###############################################################################


def _load_json_file(path, what):
    """Load JSON from `path`, failing cleanly on malformed input."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise SbomnixError(f"Missing or unreadable {what}: {path}") from error
    except json.JSONDecodeError as error:
        raise SbomnixError(f"Invalid {what} '{path}': {error}") from error


def _sarif_results(document):
    """Return validated result objects from all SARIF runs."""
    if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
        raise ValueError("SARIF must contain a runs array")
    results = []
    for run in document["runs"]:
        # A run without a results key must not silently mean zero findings:
        # as a baseline that makes everything look added, as the current
        # document it makes everything look resolved.
        if not isinstance(run, dict) or not isinstance(run.get("results"), list):
            raise ValueError("each SARIF run must contain a results array")
        if not all(isinstance(result, dict) for result in run["results"]):
            raise ValueError("each SARIF result must be an object")
        results.extend(run["results"])
    return results


def _sarif_message(result):
    message = result.get("message")
    text = message.get("text") if isinstance(message, dict) else None
    if not isinstance(text, str):
        raise ValueError("each SARIF result must contain message.text")
    return text


def _sarif_rule_id(result):
    rule_id = result.get("ruleId")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("each SARIF result must contain ruleId")
    return rule_id


def _sarif_level(result):
    level = result.get("level", "warning")
    if not isinstance(level, str):
        raise ValueError("SARIF result level must be a string")
    return level


def _sarif_fingerprint(result):
    """The versioned identity: primaryLocationLineHash."""
    fingerprints = result.get("partialFingerprints")
    fingerprint = (
        fingerprints.get("primaryLocationLineHash")
        if isinstance(fingerprints, dict)
        else None
    )
    if not isinstance(fingerprint, str) or not fingerprint:
        raise ValueError(
            f"missing primaryLocationLineHash for {_sarif_rule_id(result)}"
        )
    return fingerprint


def _sarif_group_fingerprint(result):
    """The version-independent pairing key, when the producer emitted one."""
    fingerprints = result.get("partialFingerprints")
    if not isinstance(fingerprints, dict):
        return None
    group = fingerprints.get(_GROUP_FINGERPRINT_KEY)
    return group if isinstance(group, str) and group else None


def _sarif_properties(result):
    """The producer properties object.

    Every vulnxscan SARIF result carries properties, while GitHub's
    code-scanning analyses API strips them from accepted analyses. A
    document without them was therefore likely downloaded from GitHub and
    cannot serve as a baseline: its version-independent group fingerprints
    are stripped too, so diffing it would silently report carried findings
    as resolved plus added. Fail loudly instead of emitting such a
    plausible but incorrect diff.
    """
    properties = result.get("properties")
    if not isinstance(properties, dict):
        raise ValueError(
            f"missing properties for {_sarif_rule_id(result)}: the diff "
            "requires raw vulnxscan SARIF, not a GitHub analyses download"
        )
    return properties


def _keyed_sarif_results(document):
    keyed = {}
    for result in _sarif_results(document):
        fingerprint = _sarif_fingerprint(result)
        if fingerprint in keyed:
            raise ValueError(
                f"duplicate primaryLocationLineHash for {_sarif_rule_id(result)}"
            )
        _sarif_message(result)
        _sarif_level(result)
        _sarif_properties(result)
        keyed[fingerprint] = result
    return keyed


def _sarif_semantic_message(result):
    return re.sub(r" Derivations:.*$", "", _sarif_message(result))


def _sarif_semantic_details(result, *, ignore_version):
    """Detail key for change detection: (level, details).

    Producer properties carry severity, scanners, and fix data; Nix store
    paths and GitHub alert metadata are excluded, and carried findings also
    drop the version.
    """
    cleaned = {
        key: value
        for key, value in _sarif_properties(result).items()
        if not str(key).startswith("github/")
    }
    cleaned.pop("drvPaths", None)
    cleaned.pop("storePaths", None)
    if ignore_version:
        cleaned.pop("version", None)
    details = json.dumps(cleaned, sort_keys=True, separators=(",", ":"), default=str)
    return _sarif_level(result), details


def _version_sort_key(result):
    """Sort key for carried pairing: version order, unparsable last."""
    version = _sarif_properties(result).get("version")
    version = str(version) if isinstance(version, str) else ""
    parsed = parse_version(version)
    return parsed is None, parsed, version


def _pair_sarif_results(current, previous):
    """Pair keyed current and previous results.

    Returns `(added, resolved, carried)`. Exact fingerprint matches pair
    directly and are not returned here. Leftovers pair through the
    version-independent vulnxscan/package-v1 group key: within one group
    both sides pair one-to-one in version order, so one-to-many and
    many-to-many groups pair their first min(n, m) members and the
    unpaired remainder falls back to added/resolved. Results without the
    group key can only be added or resolved.
    """
    added_candidates = [r for k, r in current.items() if k not in previous]
    resolved_candidates = [r for k, r in previous.items() if k not in current]
    previous_by_group = {}
    for index, result in enumerate(resolved_candidates):
        group = _sarif_group_fingerprint(result)
        if group is not None:
            previous_by_group.setdefault(group, []).append(index)
    for group in previous_by_group.values():
        group.sort(key=lambda i: _version_sort_key(resolved_candidates[i]))
    carried_indices = set()
    carried = []
    added = []
    for result in sorted(added_candidates, key=_version_sort_key):
        group = _sarif_group_fingerprint(result)
        candidates = previous_by_group.get(group) if group is not None else None
        if candidates:
            index = candidates.pop(0)
            carried_indices.add(index)
            carried.append((resolved_candidates[index], result))
        else:
            added.append(result)
    resolved = [
        result
        for index, result in enumerate(resolved_candidates)
        if index not in carried_indices
    ]
    return added, resolved, carried


def _bound_sarif_diff(lines, max_chars):
    """Trim trailing bullet entries until the rendered diff fits.

    Trimming only cuts at the end, so the omission note goes into the
    summary at the top rather than after the cut point. Sections whose
    entries were all trimmed are removed along with their heading.
    """
    reserve = 120  # room for the omission note below

    def render(lines):
        return "\n".join(lines).rstrip() + "\n"

    text = render(lines)
    if len(text) <= max_chars:
        return text  # fits as-is; no trimming, no omission note
    dropped = 0
    while len(text) > max_chars - reserve:
        for index in range(len(lines) - 1, -1, -1):
            if lines[index].startswith("- "):
                del lines[index]
                dropped += 1
                lines = _remove_empty_sections(lines)
                break
        else:
            break  # headers alone exceed the limit; nothing left to trim
        text = render(lines)
    if dropped:
        noun = "entry" if dropped == 1 else "entries"
        lines[4:4] = [
            "",
            f"_{dropped} further {noun} omitted to fit the size limit._",
            "",
        ]
        lines = _collapse_blank_lines(lines)
        text = render(lines)
    return text


def _remove_empty_sections(lines):
    """Drop section headings left without bullet entries after trimming."""
    kept = []
    for index, line in enumerate(lines):
        if line.startswith("### "):
            entries = itertools.takewhile(
                lambda item: not item.startswith("### "), lines[index + 1 :]
            )
            if not any(item.startswith("- ") for item in entries):
                # The removed heading leaves the blank line separating it
                # from the previous section dangling; drop that too.
                if kept and kept[-1] == "":
                    kept.pop()
                continue
        kept.append(line)
    return kept


def _collapse_blank_lines(lines):
    """Collapse consecutive blank lines into one."""
    return [
        line
        for index, line in enumerate(lines)
        if line != "" or index == 0 or lines[index - 1] != ""
    ]


def _format_finding(result):
    summary = re.split(
        r" (?:Detected by|Fixed versions reported by scanners"
        r"|Scanner fix state|Nix patch evidence|Derivations):",
        _sarif_message(result),
        maxsplit=1,
    )[0]
    return f"- {_safe_markdown_text(summary)}"


def _safe_markdown_text(text):
    """Return inert plain text safe for untrusted markdown interpolation."""
    normalized = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).strip()
    # quote=False: escaping quotes would turn ' into &#x27;, which the
    # markdown escaping below would corrupt into the literal &\#x27;.
    escaped = html.escape(normalized, quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|>~])", r"\\\1", escaped)


###############################################################################


def main():
    """main entry point"""
    args = getargs()
    set_log_verbosity(args.verbose)
    try:
        compare_sarif_files(
            args.current,
            args.markdown,
            previous=args.previous,
            max_chars=args.max_chars,
        )
    except SbomnixError as error:
        LOG.fatal("%s", error)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()

###############################################################################
