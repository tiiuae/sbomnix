#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for vulnxscan parser and reporting helpers."""

import json
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from common import columns as cols
from sbomnix.builder import SbomBuilder
from tests.testpaths import VULNXSCAN_EVIDENCE_V1
from vulnxscan.evidence import (
    build_evidence_report,
    empty_evidence_document,
    finding_id,
    validate_evidence_document,
    write_evidence_document,
)
from vulnxscan.parsers import parse_grype_json, parse_vulnix_json
from vulnxscan.reporting import (
    render_console_report,
    write_reports,
)
from vulnxscan.vulnscan import VulnScan


def test_parse_vulnix_json_updates_cvss_cache():
    """Populate vulnerability rows and severity cache from vulnix JSON."""
    cvss_cache = {}

    df = parse_vulnix_json(
        '[{"pname":"hello","version":"1.0","affected_by":["CVE-1"],'
        '"cvssv3_basescore":{"CVE-1":"7.5"}}]',
        cvss_cache=cvss_cache,
    )

    assert df.to_dict("records") == [
        {
            "package": "hello",
            "version": "1.0",
            "vuln_id": "CVE-1",
            "severity": "7.5",
            "scanner": "vulnix",
            "component_ref": "",
        }
    ]
    assert cvss_cache == {"CVE-1": "7.5"}


def test_parse_grype_json_prefers_cvss_v3_scores():
    """Select CVSS v3 severity when grype reports multiple CVSS entries."""
    cvss_cache = {}
    json_str = """
    {
      "matches": [
        {
          "artifact": {"id": "90c611e7b23a5240", "name": "hello", "version": "1.0"},
          "vulnerability": {
            "id": "CVE-2",
            "description": "Remote code execution in hello.",
            "severity": "Critical",
            "cvss": [
              {"version": "2.0", "metrics": {"baseScore": 4.0}},
              {"version": "3.1", "metrics": {"baseScore": 9.8}}
            ],
            "fix": {"state": "fixed", "versions": ["1.1", "1.2"]}
          }
        }
      ]
    }
    """

    df = parse_grype_json(json_str, cvss_cache=cvss_cache)

    assert df.to_dict("records") == [
        {
            "package": "hello",
            "version": "1.0",
            "vuln_id": "CVE-2",
            "severity": 9.8,
            "scanner": "grype",
            "component_ref": "",
            "description": "Remote code execution in hello.",
            "fix_state": "fixed",
            "fix_versions": "1.1, 1.2",
        }
    ]
    assert cvss_cache == {"CVE-2": 9.8}


def test_parse_grype_json_keeps_missing_cvss_empty():
    """Do not change the CSV severity contract when Grype has only a label."""
    json_str = """
    {
      "matches": [
        {
          "artifact": {"name": "hello", "version": "1.0"},
          "vulnerability": {
            "id": "CVE-3",
            "severity": "Negligible",
            "cvss": []
          }
        }
      ]
    }
    """

    df = parse_grype_json(json_str)

    assert df.iloc[0][cols.SEVERITY] == ""


def test_build_evidence_report_merges_scanner_counts():
    """Aggregate scanner findings into the final report layout."""
    result = build_evidence_report(
        [
            pd.DataFrame(
                [
                    {
                        "package": "hello",
                        "version": "1.0",
                        "vuln_id": "CVE-1",
                        "severity": "7.5",
                        "scanner": "vulnix",
                    }
                ]
            ),
            pd.DataFrame(
                [
                    {
                        "package": "hello",
                        "version": "1.0",
                        "vuln_id": "CVE-1",
                        "severity": "7.5",
                        "scanner": "grype",
                    }
                ]
            ),
            pd.DataFrame(),
        ],
        scanner_columns=["grype", "osv", "vulnix"],
    )
    df_report = result.report

    assert df_report.to_dict("records") == [
        {
            "vuln_id": "CVE-1",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-1",
            "package": "hello",
            "version": "1.0",
            "severity": "7.5",
            "grype": "1",
            "osv": "0",
            "vulnix": "1",
            "sum": 2,
            "sortcol": df_report.iloc[0]["sortcol"],
            "finding_id": finding_id("CVE-1", "hello", "1.0"),
            "evidence_scope": "package_version_only",
            "patch_state": "package_version_only",
            "resolved_component_count": 0,
            "vuln_id_patch_name_match_count": 0,
            "no_vuln_id_patch_name_match_count": 0,
            "metadata_unavailable_count": 0,
            "package_version_only_count": 1,
        }
    ]


def test_build_evidence_report_orders_active_findings_by_report_priority():
    """Report rows must not leak pandas groupby key ordering to users."""
    result = build_evidence_report(
        [
            None,
            pd.DataFrame(
                [
                    {
                        "package": "hello",
                        "version": "1.0",
                        "vuln_id": "CVE-2020-9999",
                        "severity": "high",
                        "scanner": "grype",
                    },
                    {
                        "package": "hello",
                        "version": "1.0",
                        "vuln_id": "CVE-2024-1",
                        "severity": "high",
                        "scanner": "grype",
                    },
                ]
            ),
            pd.DataFrame(),
        ],
        scanner_columns=["grype", "osv"],
    )
    df_report = result.report

    assert df_report[cols.VULN_ID].tolist() == ["CVE-2024-1", "CVE-2020-9999"]


def _write_sbom_csv(tmp_path, rows):
    sbom_csv = tmp_path / "sbom.csv"
    pd.DataFrame(rows).to_csv(sbom_csv, index=False)
    return sbom_csv


def _component_row(drv_path, patches, *, patch_json=None, version="1.0"):
    if patch_json is None:
        patch_json = json.dumps(patches)
    return {
        cols.STORE_PATH: drv_path,
        cols.PNAME: "hello",
        cols.VERSION: version,
        cols.OUTPUTS: [drv_path.removesuffix(".drv")],
        cols.PATCHES: " ".join(patches),
        cols.OUTPUT_PATHS_JSON: json.dumps([drv_path.removesuffix(".drv")]),
        cols.PATCH_PATHS_JSON: patch_json,
    }


def _scanner_df(vuln_id="CVE-2024-1"):
    return pd.DataFrame(
        [
            {
                cols.VULN_ID: vuln_id,
                cols.PACKAGE: "hello",
                cols.VERSION: "1.0",
                cols.SEVERITY: "high",
                cols.SCANNER: "grype",
            }
        ]
    )


def test_component_evidence_keeps_mixed_patch_evidence_active(tmp_path):
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [
            _component_row(
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-a.drv",
                ["/nix/store/src/CVE-2024-1.patch"],
            ),
            _component_row(
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-hello-b.drv",
                [],
            ),
        ],
    )

    result = build_evidence_report(
        [_scanner_df()],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    row = result.report.iloc[0]
    assert row[cols.PATCH_STATE] == "mixed_component_evidence"
    assert row[cols.RESOLVED_COMPONENT_COUNT] == 2
    assert row[cols.VULN_ID_PATCH_NAME_MATCH_COUNT] == 1
    assert row[cols.NO_VULN_ID_PATCH_NAME_MATCH_COUNT] == 1
    assert result.document["findings"][0]["suppressed_by_patch_evidence"] is False


def test_component_evidence_suppresses_only_all_matching_components(tmp_path):
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [
            _component_row(
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv",
                ["/nix/store/src/CVE-2024-1.patch"],
            ),
        ],
    )

    result = build_evidence_report(
        [_scanner_df()],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    assert result.report.empty
    assert result.document["findings"][0][cols.PATCH_STATE] == "all_components_match"
    assert result.document["findings"][0]["suppressed_by_patch_evidence"] is True
    assert result.document["components"][0]["suppressed_by_patch_evidence"] is True


def test_patch_suppression_is_announced_on_the_console(tmp_path, caplog):
    """A finding dropped as patched must still say so, and name the patch."""
    patch = "/nix/store/src/CVE-2024-1.patch"
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [
            _component_row(
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv", [patch]
            )
        ],
    )

    with caplog.at_level("INFO"):
        build_evidence_report(
            [_scanner_df()],
            sbom_csv=sbom_csv,
            scanner_columns=["grype", "osv"],
        )

    assert f"CVE-2024-1 for 'hello' is patched with: ['{patch}']" in caplog.text


def test_component_evidence_uses_documented_identity_source_names(tmp_path):
    drv_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv"
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [_component_row(drv_path, [])],
    )
    scanner_df = _scanner_df()
    scanner_df[cols.COMPONENT_REF] = drv_path

    result = build_evidence_report(
        [scanner_df],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    assert result.document["observations"][0]["resolution"] == "exact"
    assert result.document["components"][0]["identity_sources"] == [
        "scanner_component_ref"
    ]
    assert "suppressed" not in result.document["components"][0]


def test_exact_component_ref_resolves_only_that_component(tmp_path):
    selected_drv = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-selected.drv"
    sibling_drv = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-hello-sibling.drv"
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [
            _component_row(selected_drv, []),
            _component_row(sibling_drv, []),
        ],
    )
    scanner_df = _scanner_df()
    scanner_df[cols.COMPONENT_REF] = selected_drv

    result = build_evidence_report(
        [scanner_df],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    assert result.report.iloc[0][cols.RESOLVED_COMPONENT_COUNT] == 1
    assert [
        component["component_id"] for component in result.document["components"]
    ] == [selected_drv]


def test_exact_component_ref_wins_over_package_version_mismatch(tmp_path):
    """The store path is the identity when a scanner reports one."""
    drv_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dbus-0.9.10.drv"
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [
            {
                **_component_row(drv_path, []),
                cols.PNAME: "dbus-0.9.10",
                cols.VERSION: "",
            }
        ],
    )
    scanner_df = _scanner_df()
    scanner_df[cols.PACKAGE] = "dbus"
    scanner_df[cols.VERSION] = "0.9.10"
    scanner_df[cols.COMPONENT_REF] = drv_path

    result = build_evidence_report(
        [scanner_df],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    assert result.report.iloc[0][cols.EVIDENCE_SCOPE] == "component_exact"
    assert result.report.iloc[0][cols.RESOLVED_COMPONENT_COUNT] == 1
    assert result.report.iloc[0][cols.PACKAGE_VERSION_ONLY_COUNT] == 0
    assert result.document["observations"][0]["resolution"] == "exact"
    assert result.document["components"][0]["component_id"] == drv_path


def test_duplicate_scanner_observations_do_not_inflate_component_counts(tmp_path):
    drv_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv"
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [_component_row(drv_path, [])],
    )
    duplicate_rows = pd.concat([_scanner_df(), _scanner_df()], ignore_index=True)

    result = build_evidence_report(
        [duplicate_rows],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    assert result.report.iloc[0][cols.RESOLVED_COMPONENT_COUNT] == 1
    assert result.report.iloc[0][cols.SUM] == 1
    assert len(result.document["observations"]) == 1
    assert len(result.document["components"]) == 1


def _observation(scanner, observation_id):
    return {
        "observation_id": observation_id,
        cols.FINDING_ID: finding_id("CVE-1", "hello", "1.0"),
        cols.SCANNER: scanner,
        cols.VULN_ID: "CVE-1",
        cols.PACKAGE: "hello",
        cols.VERSION: "1.0",
        cols.SEVERITY: "1.0",
        cols.COMPONENT_REF: "",
        "resolution": "unresolved",
    }


def _valid_document():
    """A minimal document that satisfies every documented invariant."""
    return {
        "schema_version": 1,
        "observations": [
            _observation("grype", "observation:0"),
            _observation("osv", "observation:1"),
        ],
        "findings": [
            {
                cols.FINDING_ID: finding_id("CVE-1", "hello", "1.0"),
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "hello",
                cols.VERSION: "1.0",
                cols.SEVERITY: "1.0",
                "scanners": ["grype", "osv"],
                cols.URL: "https://nvd.nist.gov/vuln/detail/CVE-1",
                cols.SORTCOL: "CVE-1",
                cols.EVIDENCE_SCOPE: "package_version_only",
                cols.PATCH_STATE: "package_version_only",
                cols.RESOLVED_COMPONENT_COUNT: 0,
                cols.VULN_ID_PATCH_NAME_MATCH_COUNT: 0,
                cols.NO_VULN_ID_PATCH_NAME_MATCH_COUNT: 0,
                cols.METADATA_UNAVAILABLE_COUNT: 0,
                cols.PACKAGE_VERSION_ONLY_COUNT: 1,
                cols.SUPPRESSED_BY_PATCH_EVIDENCE: False,
            }
        ],
        "components": [
            {
                cols.FINDING_ID: finding_id("CVE-1", "hello", "1.0"),
                "component_id": "",
                "identity_sources": ["unresolved"],
                cols.DRV_PATH: "",
                "output_paths": [],
                cols.PNAME: "",
                cols.VERSION: "",
                cols.PATCHES: [],
                "patch_evidence_state": "package_version_only",
                "matching_patch_paths": [],
                cols.SUPPRESSED_BY_PATCH_EVIDENCE: False,
            }
        ],
    }


def test_evidence_validation_accepts_the_documented_shape():
    validate_evidence_document(_valid_document())


def test_evidence_validation_rejects_duplicate_observation_ids():
    document = _valid_document()
    document["observations"][1]["observation_id"] = "observation:0"

    with pytest.raises(AssertionError, match="Duplicate observation_id"):
        validate_evidence_document(document)


def test_evidence_validation_rejects_a_tampered_finding_digest():
    document = _valid_document()
    document["findings"][0][cols.PACKAGE] = "other"

    with pytest.raises(AssertionError, match="Invalid finding_id"):
        validate_evidence_document(document)


def test_evidence_validation_rejects_counts_that_contradict_components():
    document = _valid_document()
    document["findings"][0][cols.RESOLVED_COMPONENT_COUNT] = 3

    with pytest.raises(AssertionError, match="Invalid evidence count"):
        validate_evidence_document(document)


def test_evidence_validation_rejects_suppression_without_all_components_match():
    document = _valid_document()
    document["findings"][0][cols.SUPPRESSED_BY_PATCH_EVIDENCE] = True

    with pytest.raises(AssertionError, match="Invalid aggregate suppression state"):
        validate_evidence_document(document)


def _suppressed_document():
    """A valid document whose single finding is suppressed as fully patched."""
    document = _valid_document()
    patch = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-CVE-1.patch"
    document["components"][0].update(
        {
            "component_id": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv",
            cols.DRV_PATH: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv",
            "identity_sources": ["scanner_component_ref"],
            cols.PNAME: "hello",
            cols.VERSION: "1.0",
            cols.PATCHES: [patch],
            "patch_evidence_state": "vuln_id_patch_name_match",
            "matching_patch_paths": [patch],
            cols.SUPPRESSED_BY_PATCH_EVIDENCE: True,
        }
    )
    document["findings"][0].update(
        {
            cols.PATCH_STATE: "all_components_match",
            cols.RESOLVED_COMPONENT_COUNT: 1,
            cols.VULN_ID_PATCH_NAME_MATCH_COUNT: 1,
            cols.PACKAGE_VERSION_ONLY_COUNT: 0,
            cols.SUPPRESSED_BY_PATCH_EVIDENCE: True,
        }
    )
    return document


def test_evidence_validation_accepts_a_backed_suppression():
    validate_evidence_document(_suppressed_document())


def test_evidence_validation_rejects_a_suppression_with_no_patches():
    """A suppression must be backed by a patch, not just by a state string."""
    document = _suppressed_document()
    document["components"][0][cols.PATCHES] = []
    document["components"][0]["matching_patch_paths"] = []

    with pytest.raises(AssertionError, match="disagrees with its patches"):
        validate_evidence_document(document)


def test_evidence_validation_rejects_a_match_on_an_unrelated_patch():
    other = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-CVE-9999-1.patch"
    document = _suppressed_document()
    document["components"][0][cols.PATCHES] = [other]
    document["components"][0]["matching_patch_paths"] = [other]

    with pytest.raises(AssertionError, match="disagrees with its patches"):
        validate_evidence_document(document)


def test_evidence_validation_rejects_ignoring_a_matching_patch():
    """The reverse direction: a real patch recorded as no match."""
    document = _suppressed_document()
    document["components"][0].update(
        {
            "patch_evidence_state": "no_vuln_id_patch_name_match",
            "matching_patch_paths": [],
            cols.SUPPRESSED_BY_PATCH_EVIDENCE: False,
        }
    )
    document["findings"][0].update(
        {
            cols.PATCH_STATE: "no_component_match",
            cols.VULN_ID_PATCH_NAME_MATCH_COUNT: 0,
            cols.NO_VULN_ID_PATCH_NAME_MATCH_COUNT: 1,
            cols.SUPPRESSED_BY_PATCH_EVIDENCE: False,
        }
    )

    with pytest.raises(AssertionError, match="naming the vulnerability"):
        validate_evidence_document(document)


def test_evidence_validation_rejects_an_unknown_component_state():
    """An unknown state counts as resolved but in no category, so the
    aggregate counts would quietly stop adding up."""
    document = _valid_document()
    document["components"][0]["patch_evidence_state"] = "totally_made_up"
    document["findings"][0].update(
        {
            cols.PATCH_STATE: "no_component_match",
            cols.RESOLVED_COMPONENT_COUNT: 1,
            cols.PACKAGE_VERSION_ONLY_COUNT: 0,
        }
    )

    with pytest.raises(AssertionError, match="patch evidence state"):
        validate_evidence_document(document)


def test_evidence_validation_rejects_an_unknown_evidence_scope():
    document = _valid_document()
    document["findings"][0][cols.EVIDENCE_SCOPE] = "component_speculative"

    with pytest.raises(AssertionError, match="evidence scope"):
        validate_evidence_document(document)


def test_evidence_validation_rejects_a_scope_its_observations_deny():
    """An in-range scope is not enough: it has to match the resolutions.

    Every observation here is unresolved, so claiming an exact component match
    would overstate how the finding was identified.
    """
    document = _valid_document()
    document["findings"][0][cols.EVIDENCE_SCOPE] = "component_exact"

    with pytest.raises(AssertionError, match="evidence scope"):
        validate_evidence_document(document)


def test_evidence_validation_rejects_an_unknown_observation_resolution():
    document = _valid_document()
    document["observations"][0]["resolution"] = "telepathy"

    with pytest.raises(AssertionError, match="observation resolution"):
        validate_evidence_document(document)


def test_evidence_validation_rejects_an_observation_denying_its_finding():
    """The observation's own tuple must recompute to the finding it claims."""
    document = _valid_document()
    document["observations"][0][cols.PACKAGE] = "somethingelse"

    with pytest.raises(AssertionError, match="disagrees with its finding"):
        validate_evidence_document(document)


def test_evidence_validation_rejects_a_finding_with_no_observations():
    document = _valid_document()
    document["observations"] = []

    with pytest.raises(AssertionError, match="no observations"):
        validate_evidence_document(document)


def test_evidence_validation_rejects_dangling_references():
    document = _valid_document()
    document["components"][0][cols.FINDING_ID] = finding_id("CVE-9", "other", "9.9")

    with pytest.raises(AssertionError, match="missing finding"):
        validate_evidence_document(document)


def test_evidence_write_failure_leaves_no_partial_file(tmp_path):
    """Validation runs before the temp file is opened, so nothing is written."""
    document = _valid_document()
    document["findings"][0][cols.PACKAGE] = "other"
    out = tmp_path / "evidence.json"

    with pytest.raises(AssertionError):
        write_evidence_document(document, out)

    assert not out.exists()
    assert not list(tmp_path.iterdir())


def test_evidence_write_failure_removes_temp_file(tmp_path, monkeypatch):
    """A failed JSON write should not leave the atomic temp file behind."""
    out = tmp_path / "evidence.json"

    def failing_dump(_document, outfile, **_kwargs):
        outfile.write("{")
        raise OSError("disk full")

    monkeypatch.setattr("vulnxscan.evidence.json.dump", failing_dump)

    with pytest.raises(OSError, match="disk full"):
        write_evidence_document(_valid_document(), out)

    assert not out.exists()
    assert not (tmp_path / ".evidence.json.tmp").exists()
    assert not list(tmp_path.iterdir())


def test_evidence_document_matches_public_contract_fixture(tmp_path):
    """The emitted document must stay byte-compatible with the contract."""
    patch = "/nix/store/cccccccccccccccccccccccccccccccc-CVE-2024-1.patch"
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [
            _component_row(
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-a.drv", [patch]
            ),
            _component_row(
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-hello-b.drv", []
            ),
        ],
    )
    grype = _scanner_df()
    osv = _scanner_df()
    osv[cols.SCANNER] = "osv"
    osv[cols.SEVERITY] = "medium"

    result = build_evidence_report(
        [pd.concat([grype, osv], ignore_index=True)],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    expected = json.loads(VULNXSCAN_EVIDENCE_V1.read_text(encoding="utf-8"))
    assert result.document == expected


def test_severity_disagreement_keeps_every_raw_observation(tmp_path):
    """The aggregate takes the highest severity; observations keep them all."""
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [_component_row("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv", [])],
    )
    grype = _scanner_df()
    grype[cols.SEVERITY] = "high"
    osv = _scanner_df()
    osv[cols.SCANNER] = "osv"
    osv[cols.SEVERITY] = "critical"

    result = build_evidence_report(
        [pd.concat([grype, osv], ignore_index=True)],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    assert result.document["findings"][0][cols.SEVERITY] == "critical"
    assert sorted(
        observation[cols.SEVERITY] for observation in result.document["observations"]
    ) == ["critical", "high"]


def test_conflicting_duplicate_components_stay_active_as_metadata_unavailable(
    tmp_path,
):
    """Conflicting metadata for one component_id is resolved conservatively."""
    drv_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv"
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [
            _component_row(drv_path, ["/nix/store/src/CVE-2024-1.patch"]),
            _component_row(drv_path, []),
        ],
    )

    result = build_evidence_report(
        [_scanner_df()],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    row = result.report.iloc[0]
    assert row[cols.PATCH_STATE] == "metadata_unavailable"
    assert row[cols.RESOLVED_COMPONENT_COUNT] == 1
    assert row[cols.METADATA_UNAVAILABLE_COUNT] == 1
    assert len(result.document["components"]) == 1
    assert result.document["findings"][0][cols.SUPPRESSED_BY_PATCH_EVIDENCE] is False


def test_json_transport_columns_round_trip_paths_with_whitespace(tmp_path):
    """Paths containing spaces survive as whole entries, not split tokens."""
    spaced_patch = "/nix/store/src/my patch CVE-2024-1.patch"
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [
            _component_row(
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv",
                [spaced_patch],
            )
        ],
    )

    result = build_evidence_report(
        [_scanner_df()],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    component = result.document["components"][0]
    assert component[cols.PATCHES] == [spaced_patch]
    assert component["matching_patch_paths"] == [spaced_patch]


def test_zero_finding_scan_writes_an_empty_evidence_document(tmp_path):
    """A clean scan still produces a valid, empty, requested evidence file."""
    out = tmp_path / "vulns.csv"
    evidence_out = tmp_path / "evidence.json"
    args = SimpleNamespace(
        out=out, evidence_out=evidence_out, whitelist=None, triage=False
    )

    VulnScan().report(args, sbom_csv=None)

    assert json.loads(evidence_out.read_text(encoding="utf-8")) == (
        empty_evidence_document()
    )
    assert not out.exists()


def test_component_evidence_malformed_patch_json_is_metadata_unavailable(tmp_path):
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [
            _component_row(
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv",
                [],
                patch_json="not-json",
            ),
        ],
    )

    result = build_evidence_report(
        [_scanner_df()],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    row = result.report.iloc[0]
    assert row[cols.PATCH_STATE] == "metadata_unavailable"
    assert row[cols.METADATA_UNAVAILABLE_COUNT] == 1


def test_component_evidence_metadata_unavailable_column_is_conservative(tmp_path):
    row = _component_row("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv", [])
    row[cols.METADATA_UNAVAILABLE] = True
    sbom_csv = _write_sbom_csv(tmp_path, [row])

    result = build_evidence_report(
        [_scanner_df()],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    row = result.report.iloc[0]
    assert row[cols.PATCH_STATE] == "metadata_unavailable"
    assert row[cols.METADATA_UNAVAILABLE_COUNT] == 1


def test_component_evidence_patch_match_uses_vulnerability_id_token_boundary(tmp_path):
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [
            _component_row(
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv",
                ["/nix/store/src/CVE-2024-10.patch"],
            ),
        ],
    )

    result = build_evidence_report(
        [_scanner_df("CVE-2024-1")],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    row = result.report.iloc[0]
    assert row[cols.PATCH_STATE] == "no_component_match"
    assert row[cols.NO_VULN_ID_PATCH_NAME_MATCH_COUNT] == 1


def test_component_evidence_patch_match_ignores_directory_names(tmp_path):
    """Only the file name is evidence; a parent directory naming the
    vulnerability says nothing about what the patch changes."""
    sbom_csv = _write_sbom_csv(
        tmp_path,
        [
            _component_row(
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello.drv",
                ["/nix/store/src-CVE-2024-1/unrelated.patch"],
            ),
        ],
    )

    result = build_evidence_report(
        [_scanner_df("CVE-2024-1")],
        sbom_csv=sbom_csv,
        scanner_columns=["grype", "osv"],
    )

    row = result.report.iloc[0]
    assert row[cols.PATCH_STATE] == "no_component_match"
    assert row[cols.NO_VULN_ID_PATCH_NAME_MATCH_COUNT] == 1


def test_sbom_csv_export_adds_json_transport_columns(tmp_path):
    builder = object.__new__(SbomBuilder)
    builder.df_sbomdb = pd.DataFrame(
        [
            {
                cols.STORE_PATH: "/nix/store/hello.drv",
                cols.PNAME: "hello",
                cols.VERSION: "1.0",
                cols.OUTPUTS: ["/nix/store/hello"],
                cols.PATCHES: "/nix/store/src/CVE-2024-1.patch",
                "patch_paths": ["/nix/store/src/CVE-2024-1.patch"],
            }
        ]
    )
    csv_path = tmp_path / "sbom.csv"

    builder.to_csv(csv_path)

    exported = pd.read_csv(csv_path, keep_default_na=False)
    assert json.loads(exported.loc[0, cols.OUTPUT_PATHS_JSON]) == ["/nix/store/hello"]
    assert json.loads(exported.loc[0, cols.PATCH_PATHS_JSON]) == [
        "/nix/store/src/CVE-2024-1.patch"
    ]
    assert "patch_paths" not in exported.columns


def test_console_report_hides_csv_only_evidence_columns(caplog):
    """Evidence columns stay in CSV outputs but not the console table.

    `package_version_only_count` contains the substring "version" but holds an
    integer, which used to crash the console report on every real scan.
    """
    df_report = pd.DataFrame(
        [
            {
                cols.VULN_ID: "CVE-2024-1",
                cols.URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
                cols.PACKAGE: "hello",
                cols.VERSION: "1.0.0+verylongversionsuffix",
                cols.SEVERITY: "high",
                cols.SORTCOL: "2024A0000000001",
                cols.SUM: 1,
                cols.FINDING_ID: finding_id("CVE-2024-1", "hello", "1.0"),
                cols.EVIDENCE_SCOPE: "component_expanded",
                cols.PATCH_STATE: "mixed_component_evidence",
                cols.RESOLVED_COMPONENT_COUNT: 2,
                cols.VULN_ID_PATCH_NAME_MATCH_COUNT: 1,
                cols.NO_VULN_ID_PATCH_NAME_MATCH_COUNT: 1,
                cols.METADATA_UNAVAILABLE_COUNT: 0,
                cols.PACKAGE_VERSION_ONLY_COUNT: 0,
            }
        ]
    )

    with caplog.at_level("INFO"):
        render_console_report(df_report)

    assert "CVE-2024-1" in caplog.text
    # The version column is still truncated to 16 characters.
    assert "1.0.0+verylongve" in caplog.text
    assert "1.0.0+verylongversionsuffix" not in caplog.text
    assert cols.FINDING_ID not in caplog.text
    assert cols.EVIDENCE_SCOPE not in caplog.text
    assert cols.PATCH_STATE not in caplog.text
    assert cols.RESOLVED_COMPONENT_COUNT not in caplog.text
    assert cols.VULN_ID_PATCH_NAME_MATCH_COUNT not in caplog.text
    assert cols.NO_VULN_ID_PATCH_NAME_MATCH_COUNT not in caplog.text
    assert cols.METADATA_UNAVAILABLE_COUNT not in caplog.text
    assert cols.PACKAGE_VERSION_ONLY_COUNT not in caplog.text


def test_write_reports_writes_triage_report(tmp_path):
    """Write both the main report and the derived triage report files."""
    main_out = tmp_path / "vulns.csv"
    df_report = pd.DataFrame([{"vuln_id": "CVE-1"}])
    df_triaged = pd.DataFrame([{"vuln_id": "CVE-1", "classify": "triaged"}])

    write_reports(df_report, main_out, df_triaged=df_triaged)

    assert main_out.exists()
    assert (tmp_path / "vulns.triage.csv").exists()
    assert Path(main_out).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("buildtime", "expected_cmd"),
    [
        (False, ["vulnix", "/nix/store/my target", "-C", "--json"]),
        (True, ["vulnix", "/nix/store/my target", "--json"]),
    ],
)
def test_scan_vulnix_uses_argv_lists(monkeypatch, buildtime, expected_cmd):
    """Build vulnix subprocess argv without splitting whitespace-containing paths."""
    calls = []
    parsed = []

    def fake_exec_cmd(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(
            stdout='[{"pname": "hello", "version": "1.0", "affected_by": []}]',
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr("vulnxscan.vulnscan.exec_cmd", fake_exec_cmd)
    monkeypatch.setattr(
        VulnScan,
        "_parse_vulnix",
        lambda self, stdout: parsed.append(stdout),
    )

    VulnScan().scan_vulnix("/nix/store/my target", buildtime=buildtime)

    assert calls == [
        (
            expected_cmd,
            {"raise_on_error": False, "return_error": True, "log_error": False},
        )
    ]
    assert parsed == ['[{"pname": "hello", "version": "1.0", "affected_by": []}]']
