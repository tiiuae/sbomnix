# SPDX-License-Identifier: Apache-2.0
"""POST /sbomRiskAverage in worker/src/index.js, run under node with NVD mocked."""
import json
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests/resources/worker_harness.mjs"
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def cpe(n):
    return f"cpe:2.3:a:vendor:product{n}:1.0:*:*:*:*:*:*:*"


def bom(*cpes, nested=(), nocpe=0):
    comps = [{"type": "library", "name": f"c{i}", "version": "1", "cpe": c} for i, c in enumerate(cpes)]
    comps += [{"type": "library", "name": f"n{i}", "version": "1"} for i in range(nocpe)]
    if nested:
        comps.append({"type": "library", "name": "parent", "components": [{"type": "library", "name": "child", "cpe": c} for c in nested]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": comps}


def v31(score): return {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]}
def v30(score): return {"cvssMetricV30": [{"cvssData": {"baseScore": score}}]}
def v2(score): return {"cvssMetricV2": [{"cvssData": {"baseScore": score}}]}


def run(**sc):
    sc.setdefault("worker", str(ROOT / "worker/src/index.js"))
    p = subprocess.run(["node", str(HARNESS)], input=json.dumps(sc), capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def test_average_dedupes_cves_and_prefers_v31_then_v30_then_v2():
    r = run(file=bom(cpe(1), cpe(2)), nvd={
        cpe(1): {"status": 200, "vulns": [{"id": "CVE-A", "metrics": {**v31(9.8), **v2(1.0)}}, {"id": "CVE-B", "metrics": v2(5.0)}]},
        cpe(2): {"status": 200, "vulns": [{"id": "CVE-A", "metrics": v31(9.8)}, {"id": "CVE-C", "metrics": v30(7.0)}]}})
    b = r["body"]
    assert r["status"] == 200 and b["cves"] == 3 and b["scored_cves"] == 3
    assert b["average"] == pytest.approx((9.8 + 5.0 + 7.0) / 3, abs=0.005) and b["average"] == 7.27     # CVE-A counted once, v31 beats v2
    assert b["components_checked"] == 2 and b["partial"] is False and b["rate_limited"] is False and b["source"] == "NVD"
    assert [c["cpe"] for c in r["calls"]] == [cpe(1), cpe(2)] and all(c["hasIsVulnerable"] and c["apiKey"] is None for c in r["calls"])


def test_cve_without_any_score_is_counted_but_not_averaged():
    r = run(file=bom(cpe(1)), nvd={cpe(1): {"status": 200, "vulns": [{"id": "CVE-A", "metrics": v31(8.0)}, {"id": "CVE-NOSCORE"}]}})
    assert r["body"]["cves"] == 2 and r["body"]["scored_cves"] == 1 and r["body"]["average"] == 8.0


def test_no_cves_means_null_not_zero():
    r = run(file=bom(cpe(1)), nvd={})
    assert r["body"]["average"] is None and r["body"]["cves"] == 0 and r["body"]["components_checked"] == 1


def test_without_key_checks_at_most_five_components_and_says_so():
    r = run(file=bom(*[cpe(i) for i in range(8)]))
    b = r["body"]
    assert len(r["calls"]) == 5 and b["components_checked"] == 5 and b["components_skipped"] == 3 and b["partial"] is True
    assert "At most 5" in b["note"] or "at most 5" in b["note"]


def test_with_key_limit_is_25_and_key_is_sent_to_nvd():
    r = run(file=bom(*[cpe(i) for i in range(30)]), env={"NVD_API_KEY": "secret-key"})
    assert len(r["calls"]) == 25 and r["body"]["components_skipped"] == 5 and all(c["apiKey"] == "secret-key" for c in r["calls"])
    assert "secret-key" not in json.dumps(r["body"])                                                  # never echoed back


def test_rate_limit_stops_early_and_is_reported():
    r = run(file=bom(cpe(1), cpe(2), cpe(3)), nvd={cpe(1): {"status": 200, "vulns": [{"id": "CVE-A", "metrics": v31(6.0)}]}, cpe(2): {"status": 429}})
    b = r["body"]
    assert len(r["calls"]) == 2 and b["rate_limited"] is True and b["partial"] is True and b["components_checked"] == 1 and b["average"] == 6.0


def test_nvd_server_error_marks_partial_but_continues():
    r = run(file=bom(cpe(1), cpe(2)), nvd={cpe(1): {"status": 500}, cpe(2): {"status": 200, "vulns": [{"id": "CVE-A", "metrics": v31(4.0)}]}})
    b = r["body"]
    assert len(r["calls"]) == 2 and b["partial"] is True and b["components_checked"] == 1 and b["average"] == 4.0 and b["rate_limited"] is False


def test_components_without_cpe_and_nested_and_invalid_cpe():
    doc = bom(cpe(1), nested=(cpe(9),), nocpe=2)
    doc["components"].append({"type": "library", "name": "bad", "cpe": "not a cpe\nwith newline"})
    r = run(file=doc)
    b = r["body"]
    assert sorted(c["cpe"] for c in r["calls"]) == [cpe(1), cpe(9)]                                   # nested one found, invalid one never sent to NVD
    assert b["components_without_cpe"] == 4 and b["components_total"] == 6                            # 1 + 2 without + parent + nested child + invalid


def test_duplicate_cpes_are_looked_up_once():
    assert len(run(file=bom(cpe(1), cpe(1), cpe(1)))["calls"]) == 1


@pytest.mark.parametrize("sc,status,needle", [
    ({"method": "GET"}, 405, "POST"),
    ({"raw": "{}", "headers": {"Content-Type": "application/json"}}, 400, "multipart"),
    ({"nofile": True}, 400, "missing file"),
    ({"file": "this is not json"}, 400, "not valid JSON"),
    ({"file": {"spdxVersion": "SPDX-2.3"}}, 400, "only CycloneDX"),
    ({"file": [1, 2, 3]}, 400, "only CycloneDX"),
    ({"file": bom(cpe(1)), "headers": {"Content-Length": str(6 * 1024 * 1024)}}, 413, "too large"),
])
def test_errors_are_json_with_a_clear_message(sc, status, needle):
    r = run(**sc)
    assert r["status"] == status and needle in r["body"]["error"] and r["calls"] == []                # nothing reaches NVD on bad input


def test_cors_header_is_set_on_success_and_error():
    ok = run(file=bom(cpe(1)))
    err = run(file="nope")
    assert ok["cors"] == "https://andrzej-piotrowski-pl.github.io" and err["cors"] == "https://andrzej-piotrowski-pl.github.io"


def test_preflight_still_works():
    r = run(method="OPTIONS", headers={"Access-Control-Request-Method": "POST"})
    assert r["status"] == 204 and r["calls"] == []


def test_oversized_file_without_content_length_is_refused():
    r = run(file="x" * (5 * 1024 * 1024 + 10))
    assert r["status"] in (400, 413)


def test_other_routes_untouched():
    assert run(path="/api/health", method="GET")["body"]["status"] == "ok"
