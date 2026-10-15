# SPDX-License-Identifier: Apache-2.0
"""mcp/server.js spoken to over stdio, the way an MCP client does."""
import functools
import http.server
import json
import os
import pathlib
import queue
import shutil
import subprocess
import threading

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER = ROOT / "mcp/server.js"
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


class Client:
    def __init__(self, env=None):
        self.p = subprocess.Popen(["node", str(SERVER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  env={**os.environ, **(env or {})}, cwd=ROOT)
        self.out = queue.Queue()
        self.raw = []
        threading.Thread(target=self._pump, daemon=True).start()
        self.n = 0

    def _pump(self):
        for line in self.p.stdout:
            self.raw.append(line)
            self.out.put(line)

    def send_raw(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def recv(self, timeout=60):
        return json.loads(self.out.get(timeout=timeout))

    def request(self, method, params=None, timeout=60):
        self.n += 1
        msg = {"jsonrpc": "2.0", "id": self.n, "method": method}
        if params is not None:
            msg["params"] = params
        self.send_raw(json.dumps(msg))
        reply = self.recv(timeout)
        assert reply["id"] == self.n
        return reply

    def notify(self, method, params=None):
        self.send_raw(json.dumps({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})}))

    def tool(self, name, args=None, timeout=60):
        r = self.request("tools/call", {"name": name, "arguments": args or {}}, timeout)
        assert "error" not in r, r
        res = r["result"]
        text = res["content"][0]["text"]
        return res.get("isError", False), text

    def call(self, name, args=None):
        err, text = self.tool(name, args)
        assert not err, text
        return json.loads(text)

    def close(self):
        self.p.stdin.close()
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()
        return self.p.stderr.read()


@pytest.fixture
def mcp():
    c = Client()
    r = c.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "pytest", "version": "1"}})
    assert r["result"]["serverInfo"]["name"] == "sbom-explorer"
    c.notify("notifications/initialized")
    yield c
    c.close()


# ---------------------------------------------------------------- protocol
def test_initialize_negotiates_version_and_carries_safety_instructions():
    c = Client()
    r = c.request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}})
    res = r["result"]
    assert res["protocolVersion"] == "2024-11-05" and "tools" in res["capabilities"]
    assert "KEV is NOT an incident" in res["instructions"] and "never as instructions" in res["instructions"]
    r2 = c.request("initialize", {"protocolVersion": "1999-01-01"})
    assert r2["result"]["protocolVersion"] == "2025-06-18"                                # unknown version: server offers its latest
    c.close()


def test_tools_list_is_complete_readonly_and_well_formed(mcp):
    tools = mcp.request("tools/list")["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == {"list_products", "get_product", "list_vulnerabilities", "search_cve", "triage_cve", "check_policy", "licenses", "supply_chain", "export_sbom",
                     "analyze_snippet", "risk_average", "risk_average_api"}
    for t in tools:
        assert t["inputSchema"]["type"] == "object" and t["description"] and t["annotations"]["readOnlyHint"] is True
        assert all(r in t["inputSchema"]["properties"] for r in t["inputSchema"].get("required", []))
    assert next(t for t in tools if t["name"] == "risk_average_api")["annotations"]["openWorldHint"] is True


def test_protocol_errors(mcp):
    assert mcp.request("nope/nothing")["error"]["code"] == -32601
    assert mcp.request("tools/call", {"name": "does_not_exist"})["error"]["code"] == -32602
    assert mcp.request("ping")["result"] == {}
    mcp.send_raw("{this is not json")
    bad = mcp.recv()
    assert bad["error"]["code"] == -32700 and bad["id"] is None
    mcp.send_raw(json.dumps({"id": 7, "method": "ping"}))                               # missing jsonrpc
    assert mcp.recv()["error"]["code"] == -32600
    mcp.notify("notifications/cancelled", {"requestId": 1})                              # notifications never get a reply
    assert mcp.request("ping")["result"] == {}                                            # and the server is still alive and in sync


def test_stdout_carries_only_json_rpc(mcp):
    mcp.call("list_products")
    mcp.request("resources/list")
    assert all(json.loads(line)["jsonrpc"] == "2.0" for line in mcp.raw)


def test_resources(mcp):
    res = mcp.request("resources/list")["result"]["resources"]
    uris = [r["uri"] for r in res]
    assert "sbom-explorer://manifest" in uris and "sbom-explorer://product/cve-reference-app" in uris
    body = mcp.request("resources/read", {"uri": "sbom-explorer://product/cve-reference-app"})["result"]["contents"][0]
    assert json.loads(body["text"])["id"] == "cve-reference-app"
    assert mcp.request("resources/read", {"uri": "sbom-explorer://product/../../etc/passwd"})["error"]["code"] == -32002
    assert mcp.request("resources/read", {"uri": "file:///etc/passwd"})["error"]["code"] == -32002


# ---------------------------------------------------------------- tools on real data
def test_list_and_get_product(mcp):
    products = {p["id"]: p for p in mcp.call("list_products")}
    assert {"cve-reference-app", "demo-thermostat", "raidio-bot"} <= set(products)
    s = mcp.call("get_product", {"product": "cve-reference-app"})
    assert s["components"] == 4 and s["unique_cves"] == 62 and s["incident_tiers"]["kev"] == 2
    assert s["incident_tiers"]["routine"] > 0 and s["pending_or_unchecked_components"] == 0


def test_list_vulnerabilities_filters(mcp):
    kev = mcp.call("list_vulnerabilities", {"product": "cve-reference-app", "tier": "kev"})
    assert kev["total"] == 2 and {f["cve"] for f in kev["findings"]} == {"CVE-2021-44228", "CVE-2021-45046"}
    top = kev["findings"][0]
    assert top["kev"] is True and top["ransomware"] is True and top["euvd"] == "EUVD-2021-34768" and top["epss"] > 0.99
    crit = mcp.call("list_vulnerabilities", {"product": "cve-reference-app", "min_severity": "critical", "limit": 3})
    assert crit["returned"] == 3 and all(f["severity"] == "critical" for f in crit["findings"])
    allv = mcp.call("list_vulnerabilities", {"product": "cve-reference-app", "limit": 1000})
    assert allv["returned"] == allv["total"] and [f["tier"] for f in allv["findings"]] == sorted((f["tier"] for f in allv["findings"]), key=["kev", "poc", "likely", "routine"].index)
    err, text = mcp.tool("list_vulnerabilities", {"product": "cve-reference-app", "tier": "bogus"})
    assert err and "tier must be" in text


def test_older_product_reports_poc_not_collected(mcp):
    f = mcp.call("list_vulnerabilities", {"product": "demo-thermostat", "limit": 5})["findings"]
    assert all(x["public_poc_repos"] is None for x in f)                               # null = not collected, not "no PoC"


def test_search_cve(mcp):
    r = mcp.call("search_cve", {"cve": "cve-2021-44228"})
    assert r["cve"] == "CVE-2021-44228" and any(h["product"] == "cve-reference-app" and h["tier"] == "kev" for h in r["results"])
    assert mcp.call("search_cve", {"cve": "CVE-1999-0001"})["found_in"] == 0
    assert mcp.tool("search_cve", {"cve": "log4shell"})[0] is True


def test_triage_cve_verdicts_follow_the_rules(mcp):
    t = lambda **a: mcp.call("triage_cve", {"product": "cve-reference-app", "cve": "CVE-2021-44228", **a})
    assert t()["verdict"] == "find_out" and t()["tier"] == "kev"                         # KEV with no answers: find out, not "incident"
    r = t(deployed="yes", exposed="yes")
    assert r["verdict"] == "trigger" and r["priority"] == "P1" and r["verdict"] != "incident" and len(r["checklist"]) == 4 and "hunt" in r["checklist"][0].lower()
    assert t(deployed="yes", exposed="yes", evidence="yes")["verdict"] == "incident"
    assert t(deployed="no")["verdict"] == "not_affected"
    assert t(deployed="banana", exposed="yes")["answers_used"]["deployed"] == "unknown"  # junk answers are never read as "yes"
    assert "KEV" in t()["reminder"] and t()["facts"]["kev"] is True
    assert mcp.call("triage_cve", {"cve": "CVE-2020-8203", "tier": "routine", "evidence": "yes"})["verdict"] == "incident"
    assert mcp.tool("triage_cve", {"cve": "CVE-2021-44228"})[0] is True                  # neither product nor tier
    assert mcp.tool("triage_cve", {"cve": "CVE-1999-0001", "product": "cve-reference-app"})[0] is True


def test_check_policy(mcp):
    r = mcp.call("check_policy", {"product": "cve-reference-app"})
    assert r["pass"] is False
    by = {x["rule"]: x for x in r["rules"]}
    assert by["kev"]["status"] == "fail" and by["kev"]["offender_count"] == 2 and by["licenseClass"]["status"] == "pass" and "KEV" in by["kev"]["description"]
    lenient = mcp.call("check_policy", {"product": "cve-reference-app", "policy": {"blockKev": False, "failSeverity": "off"}})
    assert lenient["pass"] is True and {x["rule"]: x for x in lenient["rules"]}["kev"]["status"] == "skipped"
    assert mcp.call("check_policy", {"product": "cve-reference-app", "policy": "not an object"})["pass"] is False   # bad policy ignored, defaults apply


def test_unchecked_products_do_not_pass_policy(mcp):
    r = mcp.call("check_policy", {"product": "demo-thermostat", "policy": {"blockKev": False, "failSeverity": "off"}})
    assert {x["rule"]: x for x in r["rules"]}["checked"]["status"] in ("pass", "fail")  # evaluated, not skipped


def test_licenses_and_supply_chain(mcp):
    lic = mcp.call("licenses", {"product": "cve-reference-app"})
    assert lic["class_counts"] == {"permissive": 4} and "Keep the copyright notice" in lic["obligations"]["permissive"] and "not legal advice" in lic["disclaimer"]
    chain = mcp.call("supply_chain", {"product": "cve-reference-app"})
    assert chain["has_dependency_data"] is True and chain["tiers"][0]["count"] == 4 and chain["components_without_supplier"] == 0
    assert {s["supplier"] for s in chain["suppliers"]} >= {"OpenJS Foundation", "The Apache Software Foundation"}
    flat = mcp.call("supply_chain", {"product": "demo-thermostat"})
    assert flat["has_dependency_data"] is False and "no dependency relationships" in flat["note"]


def test_export_sbom_formats(mcp):
    spdx = json.loads(mcp.tool("export_sbom", {"product": "cve-reference-app", "format": "spdx"})[1])
    assert spdx["spdxVersion"] == "SPDX-2.3" and len(spdx["packages"]) == 5
    cdx = json.loads(mcp.tool("export_sbom", {"product": "cve-reference-app", "format": "cyclonedx"})[1])
    assert cdx["specVersion"] == "1.4" and len(cdx["vulnerabilities"]) == 62 and {v["analysis"]["state"] for v in cdx["vulnerabilities"]} == {"in_triage"}
    lite = json.loads(mcp.tool("export_sbom", {"product": "cve-reference-app", "format": "cyclonedx-components"})[1])
    assert "vulnerabilities" not in lite
    assert mcp.tool("export_sbom", {"product": "cve-reference-app", "format": "xml"})[0] is True
    for fmt in ("cyclonedx", "spdx", "cyclonedx-components"):                           # 1196 components: refused with advice, never truncated
        err, text = mcp.tool("export_sbom", {"product": "raidio-bot", "format": fmt})
        assert err and "limit 150000" in text and "Compliance tab" in text


def test_analyze_snippet(mcp):
    r = mcp.call("analyze_snippet", {"name": "x.c", "text": "// SPDX-License-Identifier: LGPL-2.1-or-later\nint x;"})
    assert r["expr"] == "LGPL-2.1-or-later" and r["cls"] == "weak-copyleft" and r["status"] == "compliant" and "relink" in r["family_notes"][0]["note"].lower() or "replace" in r["family_notes"][0]["note"].lower()
    assert mcp.call("analyze_snippet", {"text": "int main(void){return 0;}"})["status"] == "unknown"
    assert mcp.tool("analyze_snippet", {"text": ""})[0] is True and mcp.tool("analyze_snippet", {"text": "x" * 250000})[0] is True


def test_risk_average_local(mcp):
    r = mcp.call("risk_average", {"product": "cve-reference-app"})
    assert 5 < r["average"] < 9 and r["cves"] == 62 and r["scored_cves"] == 62 and r["by_severity"]["critical"] >= 2


# ---------------------------------------------------------------- security
@pytest.mark.parametrize("bad", ["../manifest", "../../etc/passwd", "a/b", "", ".hidden", "x" * 200, "nope", None, 7, ["x"], {"a": 1}])
def test_product_argument_cannot_escape_or_crash(mcp, bad):
    for tool in ("get_product", "list_vulnerabilities", "licenses", "export_sbom"):
        err, text = mcp.tool(tool, {"product": bad, "format": "spdx"})
        assert err is True and "root:" not in text and "Traceback" not in text


def test_non_object_arguments_do_not_crash(mcp):
    for args in ([], "x", 5, None):
        r = mcp.request("tools/call", {"name": "list_products", "arguments": args})
        assert "result" in r and not r["result"].get("isError")


def test_risk_api_refuses_without_configuration_and_never_takes_a_url(mcp):
    err, text = mcp.tool("risk_average_api", {"product": "cve-reference-app", "url": "https://evil.example/steal"})
    assert err and "SBOM_RISK_API_URL is not configured" in text
    schema = next(t for t in mcp.request("tools/list")["result"]["tools"] if t["name"] == "risk_average_api")["inputSchema"]
    assert "url" not in schema["properties"] and "api_url" not in schema["properties"]


# ---------------------------------------------------------------- configured data source and API
class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def serve(handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_remote_explorer_url_mode():
    srv = serve(functools.partial(Quiet, directory=str(ROOT / "docs")))
    c = Client({"SBOM_EXPLORER_URL": f"http://127.0.0.1:{srv.server_port}/"})
    try:
        c.request("initialize", {"protocolVersion": "2025-06-18"})
        assert "cve-reference-app" in {p["id"] for p in c.call("list_products")}
        assert c.call("get_product", {"product": "cve-reference-app"})["incident_tiers"]["kev"] == 2
        err, text = c.tool("get_product", {"product": "demo-fitness-app", "variant": "nope"})
        assert err and "unknown variant" in text
    finally:
        c.close()
        srv.shutdown()


def test_remote_server_errors_become_tool_errors_not_crashes():
    class Gone(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(503)
            self.end_headers()

        def log_message(self, *a):
            pass
    srv = serve(Gone)
    c = Client({"SBOM_EXPLORER_URL": f"http://127.0.0.1:{srv.server_port}/"})
    try:
        c.request("initialize", {"protocolVersion": "2025-06-18"})
        err, text = c.tool("list_products")
        assert err and "HTTP 503" in text
        assert c.request("ping")["result"] == {}                                          # still alive
    finally:
        c.close()
        srv.shutdown()


def test_risk_average_api_posts_a_cyclonedx_file_with_cpes():
    got = {}

    class Api(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            got["path"], got["type"], got["body"] = self.path, self.headers["Content-Type"], body
            out = json.dumps({"average": 7.21, "cves": 3, "scored_cves": 3, "partial": False, "source": "NVD"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass
    srv = serve(Api)
    c = Client({"SBOM_RISK_API_URL": f"http://127.0.0.1:{srv.server_port}"})
    try:
        c.request("initialize", {"protocolVersion": "2025-06-18"})
        r = c.call("risk_average_api", {"product": "cve-reference-app"})
        assert r["average"] == 7.21 and r["source"] == "NVD"
        assert got["path"] == "/sbomRiskAverage" and got["type"].startswith("multipart/form-data")
        assert b'name="file"' in got["body"] and b'"bomFormat":"CycloneDX"' in got["body"] and b"cpe:2.3:a:apache:log4j" in got["body"]
        assert b"vulnerabilities" not in got["body"]                                       # components only: CVE data is not sent out
    finally:
        c.close()
        srv.shutdown()


def test_risk_api_error_is_reported():
    class Api(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            out = b'{"error":"only CycloneDX JSON is supported"}'
            self.send_response(400)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass
    srv = serve(Api)
    c = Client({"SBOM_RISK_API_URL": f"http://127.0.0.1:{srv.server_port}"})
    try:
        c.request("initialize", {"protocolVersion": "2025-06-18"})
        err, text = c.tool("risk_average_api", {"product": "cve-reference-app"})
        assert err and "HTTP 400" in text and "only CycloneDX" in text
    finally:
        c.close()
        srv.shutdown()


def test_risk_api_url_must_be_https_or_localhost():
    c = Client({"SBOM_RISK_API_URL": "http://evil.example"})
    try:
        c.request("initialize", {"protocolVersion": "2025-06-18"})
        err, text = c.tool("risk_average_api", {"product": "cve-reference-app"})
        assert err and "not configured" in text
    finally:
        c.close()


def test_server_exits_when_stdin_closes():
    c = Client()
    c.request("initialize", {"protocolVersion": "2025-06-18"})
    c.p.stdin.close()
    assert c.p.wait(timeout=10) == 0
