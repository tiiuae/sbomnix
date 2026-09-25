#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for the vulnxscan SARIF diff."""

import json

import pandas as pd
import pytest

from common import columns as cols
from vulnxscan.sarif import findings_to_sarif
from vulnxscan.sarif_diff import compare_sarif_files, getargs, render_sarif_diff


def _sarif_result(rule_id, package, version, fingerprint, level="warning"):
    group = f"group-{rule_id}-{package}"
    affected = " ".join(value for value in (package, version) if value)
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {
            "text": (
                f"{rule_id} affects {affected}. Severity: {level}. "
                f"Detected by: grype Derivations: /nix/store/{fingerprint[:8]}"
            )
        },
        "partialFingerprints": {
            "primaryLocationLineHash": fingerprint,
            "vulnxscan/package-v1": group,
        },
        "properties": {
            "package": package,
            "version": version,
            "severity": level,
            "drvPaths": [f"/nix/store/{fingerprint[:8]}"],
        },
    }


def _sarif_document(*results):
    return {"version": "2.1.0", "runs": [{"results": list(results)}]}


def test_render_no_baseline():
    current = _sarif_document(_sarif_result("CVE-1", "pkg", "1.0", "a" * 64))

    report = render_sarif_diff(current, None)

    assert "No previous SARIF baseline available (1 current)." in report


def test_render_classifies_added_resolved_changed_carried():
    previous = _sarif_document(
        _sarif_result("CVE-CARRIED", "carried", "1.0", "a" * 64),
        _sarif_result("CVE-CHANGED", "changed", "1.0", "b" * 64, "warning"),
        _sarif_result("CVE-RESOLVED", "resolved", "1.0", "c" * 64),
    )
    current = _sarif_document(
        _sarif_result("CVE-CARRIED", "carried", "2.0", "d" * 64),
        _sarif_result("CVE-CHANGED", "changed", "1.0", "b" * 64, "error"),
        _sarif_result("CVE-ADDED", "added", "1.0", "e" * 64),
    )

    report = render_sarif_diff(current, previous)

    assert (
        "3 current, 1 added, 1 resolved, 1 changed; "
        "1 persisted across package version updates." in report
    )
    assert "### Added" in report
    assert "CVE\\-ADDED affects added 1\\.0\\." in report
    assert "### Resolved" in report
    assert "CVE\\-RESOLVED affects resolved 1\\.0\\." in report
    assert "### Changed" in report
    assert "**CVE\\-CHANGED**" in report
    # The carried finding is neither added nor resolved, and the report never
    # leaks store paths.
    assert "CVE\\-CARRIED" not in report
    assert "/nix/store/" not in report


def test_render_reports_carried_detail_changes():
    previous = _sarif_document(
        _sarif_result("CVE-1", "pkg", "1.0", "a" * 64, "warning")
    )
    current = _sarif_document(_sarif_result("CVE-1", "pkg", "2.0", "b" * 64, "error"))

    report = render_sarif_diff(current, previous)

    assert "1 changed; 1 persisted across package version updates." in report
    assert "**CVE\\-1**" in report


def test_render_pairs_groups_one_to_one():
    # Many-to-many within one (rule, package) group: two previous versions,
    # one current version. The extra previous result stays resolved.
    previous = _sarif_document(
        _sarif_result("CVE-1", "pkg", "1.0", "a" * 64),
        _sarif_result("CVE-1", "pkg", "1.1", "b" * 64),
    )
    current = _sarif_document(_sarif_result("CVE-1", "pkg", "2.0", "c" * 64))

    report = render_sarif_diff(current, previous)

    assert "1 current, 0 added, 1 resolved, 0 changed; 1 persisted" in report


def test_render_without_group_key_cannot_carry():
    previous_result = _sarif_result("CVE-1", "pkg", "1.0", "a" * 64)
    previous_result["partialFingerprints"].pop("vulnxscan/package-v1")
    current_result = _sarif_result("CVE-1", "pkg", "2.0", "b" * 64)

    report = render_sarif_diff(
        _sarif_document(current_result), _sarif_document(previous_result)
    )

    assert "1 current, 1 added, 1 resolved, 0 changed." in report


def test_render_ignores_github_properties_and_store_paths():
    previous_result = _sarif_result("CVE-1", "pkg", "1.0", "a" * 64)
    previous_result["properties"]["github/alertNumber"] = 7
    previous_result["properties"]["drvPaths"] = ["/nix/store/other"]
    current_result = _sarif_result("CVE-1", "pkg", "1.0", "a" * 64)

    report = render_sarif_diff(
        _sarif_document(current_result), _sarif_document(previous_result)
    )

    assert "No finding additions, resolutions, or detail changes" in report


def test_render_escapes_apostrophes_without_double_escaping():
    current = _sarif_document(_sarif_result("CVE-1", "o'brien", "1.0", "a" * 64))

    report = render_sarif_diff(current, _sarif_document())

    assert "o'brien" in report
    assert "&#x27;" not in report
    assert "&\\#x27;" not in report


def test_render_rejects_run_without_results_array():
    with pytest.raises(ValueError, match="results array"):
        render_sarif_diff({"runs": [{}]})


def test_render_rejects_duplicate_fingerprints():
    document = _sarif_document(
        _sarif_result("CVE-1", "pkg", "1.0", "a" * 64),
        _sarif_result("CVE-1", "pkg", "2.0", "a" * 64),
    )

    with pytest.raises(ValueError, match="duplicate primaryLocationLineHash"):
        render_sarif_diff(document, _sarif_document())


def test_render_is_unbounded_by_default():
    current = _sarif_document(
        *(
            _sarif_result(f"CVE-2026-{index}", f"pkg{index}", "1.0", f"{index:064d}")
            for index in range(2000)
        )
    )

    report = render_sarif_diff(current, _sarif_document())

    assert len(report) > 60000
    assert "omitted" not in report


def test_render_max_chars_bounds_output():
    current = _sarif_document(
        *(
            _sarif_result(f"CVE-2026-{index}", f"pkg{index}", "1.0", f"{index:064d}")
            for index in range(2000)
        )
    )

    report = render_sarif_diff(current, _sarif_document(), max_chars=60000)

    assert len(report) <= 60000
    assert "omitted to fit the size limit" in report
    # The omission note sits in the top summary, before any cut content.
    assert report.index("omitted to fit the size limit") < report.index("### Added")


def test_render_max_chars_returns_untrimmed_when_fitting():
    current = _sarif_document(
        *(
            _sarif_result(f"CVE-2026-{index}", f"pkg{index}", "1.0", f"{index:064d}")
            for index in range(3)
        )
    )

    untrimmed = render_sarif_diff(current, _sarif_document())
    bounded = render_sarif_diff(
        current, _sarif_document(), max_chars=len(untrimmed) + 100
    )

    assert bounded == untrimmed
    assert "omitted" not in bounded


def test_render_max_chars_removes_emptied_sections():
    current = _sarif_document(
        *(
            _sarif_result(f"CVE-2026-{index}", f"pkg{index}", "1.0", f"{index:064d}")
            for index in range(50)
        )
    )
    previous = _sarif_document(_sarif_result("CVE-1", "pkg", "1.0", "f" * 64))
    # Bound the output so the trailing Resolved section's only entry is
    # trimmed; its heading must not linger as an empty section.
    bounded = render_sarif_diff(current, previous, max_chars=400)

    assert "### Resolved" not in bounded
    assert "CVE\\-1 affects pkg" not in bounded
    assert "### Added" in bounded
    assert "\n\n\n" not in bounded


def test_compare_sarif_files_missing_previous_means_no_baseline(tmp_path):
    current = tmp_path / "current.sarif"
    current.write_text(json.dumps(_sarif_document()), encoding="utf-8")
    markdown = tmp_path / "diff.md"

    compare_sarif_files(
        current,
        markdown,
        previous=tmp_path / "absent.sarif",
    )

    assert "No previous SARIF baseline available (0 current)." in markdown.read_text(
        encoding="utf-8"
    )


def test_getargs_rejects_non_positive_max_chars():
    with pytest.raises(SystemExit):
        getargs(
            [
                "--current",
                "a.sarif",
                "--markdown",
                "b.md",
                "--max-chars",
                "0",
            ]
        )


def test_compare_sarif_files_replaces_stale_output(tmp_path):
    current = tmp_path / "current.sarif"
    current.write_text(json.dumps(_sarif_document()), encoding="utf-8")
    markdown = tmp_path / "diff.md"
    markdown.write_text("stale", encoding="utf-8")

    compare_sarif_files(current, markdown)

    assert "stale" not in markdown.read_text(encoding="utf-8")


def _produced_sarif(version, severity="high"):
    """Real producer output for one finding at `version`."""
    frame = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "hello",
                cols.VERSION_LOCAL: version,
                cols.SEVERITY: severity,
                "grype": "1",
            }
        ]
    )
    return findings_to_sarif(frame, tool_version="1.8.0")


def test_producer_output_carries_across_version_update():
    """Producer and diff agree: a version bump is carried, not added/resolved."""
    previous = _produced_sarif("1.0")
    current = _produced_sarif("2.0")

    report = render_sarif_diff(current, previous)

    assert "No finding additions, resolutions, or detail changes" in report
    assert "1 persisted across package version updates" in report


def test_producer_output_reports_severity_change_on_carried():
    previous = _produced_sarif("1.0", severity="high")
    current = _produced_sarif("2.0", severity="critical")

    report = render_sarif_diff(current, previous)

    assert "1 changed; 1 persisted across package version updates" in report
