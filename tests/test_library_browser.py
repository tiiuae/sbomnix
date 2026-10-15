# SPDX-License-Identifier: Apache-2.0
"""The SBOM library in a real (headless) browser: import, open, check, update, remove. External services are mocked unless a test says otherwise."""
import functools
import glob
import http.server
import json
import os
import pathlib
import subprocess
import threading
from datetime import datetime, timedelta, timezone

import pytest

playwright_sync = pytest.importorskip("playwright.sync_api")

ROOT = pathlib.Path(__file__).resolve().parents[1]
REF = ROOT / "docs/reference-sbom/reference.cdx.json"
CHROMES = sorted(glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell")))
pytestmark = pytest.mark.skipif(not CHROMES, reason="no headless chromium for playwright")
INIT = "try{localStorage.setItem('tour-home','1');localStorage.setItem('tour-product','1')}catch(e){}"

LOG4SHELL = {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"], "summary": "Remote code injection in Log4j", "published": "2021-12-10T00:40:56Z",
             "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]}
KEV = {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known"}]}
TABS = ["overview", "history", "compare", "actions", "ir", "maturity", "quality", "compliance", "supplychain", "components", "evidence", "sbom"]


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def site():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=str(ROOT / "docs")))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/"
    srv.shutdown()


@pytest.fixture(scope="module")
def browser():
    with playwright_sync.sync_playwright() as p:
        b = p.chromium.launch(executable_path=CHROMES[-1])
        yield b
        b.close()


class Page:
    """A fresh browser profile (empty IndexedDB) with the external services answered from canned data."""
    def __init__(self, browser, site, offline_services=False, kev_status=200):
        self.ctx = browser.new_context(viewport={"width": 1300, "height": 1000}, accept_downloads=True)
        self.page = self.ctx.new_page()
        self.page.add_init_script(INIT)
        self.site, self.errors, self.calls = site, [], []
        self.kev_status = kev_status
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.page.route(lambda url: not url.startswith(site) and not url.startswith("data:"), self._external)

    def _external(self, route):
        req = route.request
        url = req.url
        self.calls.append((req.method, url))
        cors = {"Access-Control-Allow-Origin": "*"}
        ok = lambda body, status=200: route.fulfill(status=status, headers=cors, content_type="application/json", body=json.dumps(body))
        if url.endswith("/v1/querybatch"):
            queries = json.loads(req.post_data)["queries"]
            return ok({"results": [{"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q"}]} if "log4j-core" in q["package"]["purl"] else {} for q in queries]})
        if "/v1/vulns/GHSA-jfh8" in url:
            return ok(LOG4SHELL)
        if "known_exploited" in url:
            return ok(KEV, self.kev_status) if self.kev_status == 200 else route.fulfill(status=self.kev_status, headers=cors, body="")
        if "first.org" in url:
            return ok({"data": [{"cve": "CVE-2021-44228", "epss": "0.99999"}]})
        if "PoC-in-GitHub" in url:
            return ok([{"html_url": "https://github.com/x/poc"}]) if "CVE-2021-44228" in url else route.fulfill(status=404, headers=cors, body="[]")
        route.fulfill(status=404, headers=cors, body="")

    def go(self, hash_):
        self.page.goto(self.site + hash_)
        self.page.wait_for_timeout(700)

    def fresh(self, hash_):
        """A real page load (not just a hash change): this is when the Explorer runs its auto-update."""
        self.page.goto("about:blank")
        self.go(hash_)

    def fresh(self, hash_):
        """A real page load (not just a hash change): this is when the Explorer runs its auto-update."""
        self.page.goto("about:blank")
        self.go(hash_)

    def osv_calls(self):
        return [c for c in self.calls if "api.osv.dev" in c[1]]

    def records(self):
        return self.page.evaluate("""() => new Promise((res, rej) => { const r = indexedDB.open('sbom-explorer-library'); r.onsuccess = () => { const db = r.result;
            const q = db.transaction('sboms').objectStore('sboms').getAll(); q.onsuccess = () => res(q.result.map(x => ({id: x.id, checkedAt: x.checkedAt, lastError: x.lastError, origin: x.origin, srcName: x.srcName, vuln_total: Object.values(x.product.variants)[0].history[0].vuln_total, name: x.brief.name}))); }; r.onerror = () => rej(r.error); })""")

    def set_checked_at(self, id_, iso):
        self.page.evaluate("""([id, iso]) => new Promise((res, rej) => { const r = indexedDB.open('sbom-explorer-library'); r.onsuccess = () => { const db = r.result, tx = db.transaction('sboms', 'readwrite'), st = tx.objectStore('sboms');
            st.get(id).onsuccess = e => { const rec = e.target.result; rec.checkedAt = iso; rec.lastTry = ''; st.put(rec); }; tx.oncomplete = () => res(); }; r.onerror = () => rej(r.error); })""", [id_, iso])

    def import_file(self, path, check=True, origin=None, label=None, name=None):
        self.go("#/library")
        if not check:
            self.page.uncheck("#libCheckBox")
        if origin:
            self.page.select_option("#libOrigin", origin)
        if label:
            self.page.fill("#libSource", label)
        if name:
            self.page.fill("#libName", name)
        self.page.set_input_files("#libFile", str(path))
        self.page.wait_for_timeout(1800 if check else 900)

    def close(self):
        self.ctx.close()


@pytest.fixture
def pg(browser, site):
    p = Page(browser, site)
    yield p
    assert p.errors == [], p.errors            # no test may leave a JavaScript error behind
    p.close()


def test_import_check_and_open_every_tab(pg):
    pg.import_file(REF, origin="third-party", label="ACME Corp")
    rec = pg.records()
    assert len(rec) == 1 and rec[0]["origin"] == "third-party" and rec[0]["checkedAt"] and rec[0]["vuln_total"] == 1 and rec[0]["lastError"] == ""
    row = pg.page.locator("#libRows tr").first.inner_text()
    assert "cve-reference-app" in row and "third-party" in row and "ACME Corp" in row and "1 CVE" in row and "KEV ×1" in row
    assert "not covered" in row                                                              # openssl's generic purl is not covered by OSV: said, not hidden
    assert pg.page.locator(".kpis .kpi").first.inner_text().split("\n")[-1] == "1"
    pg.go("#/")
    assert "third-party" in pg.page.locator(".card .badge", has_text="third-party").first.inner_text()
    pid = rec[0]["id"]
    for tab in TABS:
        pg.go(f"#/p/{pid}/imported/{tab}" if tab != "overview" else f"#/p/{pid}")
        assert "Could not load" not in pg.page.inner_text("#app"), tab
    pg.go(f"#/p/{pid}/imported/ir")
    pg.page.select_option("#irFilter", "kev")
    assert [r.split("\t")[1] for r in pg.page.locator("#irBody tr").all_inner_texts()] == ["CVE-2021-44228"]
    assert pg.page.locator(".card.warn b", has_text="No CVE data yet").count() == 0          # it has been checked
    pg.go(f"#/p/{pid}/imported/overview")
    assert "imported" in pg.page.locator("h2 .badge").nth(1).inner_text() or "third-party" in pg.page.inner_text("h2")


def test_unchecked_import_is_labelled_not_safe(pg):
    pg.import_file(REF, check=False)
    rec = pg.records()
    assert len(rec) == 1 and rec[0]["checkedAt"] is None and pg.osv_calls() == []             # no lookups without the user's say-so
    assert "not checked" in pg.page.locator("#libRows tr").first.inner_text()
    pid = rec[0]["id"]
    pg.go(f"#/p/{pid}/imported/overview")
    assert "not been checked" in pg.page.inner_text("#app")
    pg.go(f"#/p/{pid}/imported/ir")
    assert pg.page.locator(".card.warn b", has_text="No CVE data yet").count() == 1
    pg.go(f"#/p/{pid}/imported/compliance")
    pg.page.wait_for_timeout(500)
    assert "unchecked is not clean" in pg.page.inner_text("#compBody").lower() or "CVE-checked" in pg.page.inner_text("#compBody")


def spdx_file(tmp_path):
    prod = json.loads((ROOT / "docs/data/cve-reference-app.json").read_text())["variants"]["reference"]
    code = ("const c=require(process.argv[1]+'/docs/compliance.js'),t=require(process.argv[1]+'/docs/data/licenses.json');const v=JSON.parse(require('fs').readFileSync(0,'utf8'));"
            "process.stdout.write(JSON.stringify(c.toSPDX({product:'spdx-app',version:'7',rows:c.licenseRows(v,t)})))")
    out = subprocess.run(["node", "-e", code, str(ROOT)], input=json.dumps(prod), capture_output=True, text=True, check=True).stdout
    f = tmp_path / "exported.spdx.json"
    f.write_text(out)
    return f


def test_spdx_import(pg, tmp_path):
    pg.import_file(spdx_file(tmp_path), check=False, name="From SPDX")
    rec = pg.records()
    assert [r["name"] for r in rec] == ["From SPDX"]
    pid = rec[0]["id"]
    pg.go(f"#/p/{pid}/imported/components")
    names = [r.split("\t")[0] for r in pg.page.locator("#cbody tr").all_inner_texts()]
    assert sorted(names) == ["log4j-core", "lodash", "openssl", "requests"] or sorted(names) == sorted(["log4j-core", "requests", "lodash", "openssl"])
    pg.go(f"#/p/{pid}/imported/sbom")
    assert "SPDX" in pg.page.inner_text("#app")


def test_bad_files_are_refused_with_a_reason_and_nothing_is_stored(pg, tmp_path):
    for name, body, needle in [("a.xml", "<bom/>", "XML is not supported"), ("b.json", "{nope", "not valid JSON"), ("c.json", '{"hello": 1}', "not a CycloneDX or SPDX"), ("d.json", "", "empty")]:
        f = tmp_path / name
        f.write_text(body)
        pg.import_file(f, check=False)
        msg = pg.page.inner_text("#libMsg")
        assert name in msg and needle in msg, (name, msg)
    assert pg.records() == []


def test_same_sbom_twice_gets_distinct_entries_and_can_be_removed(pg):
    pg.import_file(REF, check=False)
    pg.import_file(REF, check=False)
    ids = sorted(r["id"] for r in pg.records())
    assert ids == ["local-cve-reference-app", "local-cve-reference-app-2"]
    pg.page.on("dialog", lambda d: d.accept())
    pg.page.locator("#libRows tr", has_text="local-cve-reference-app-2").count()
    pg.page.locator("#libRows tr").nth(0).locator("button[data-act=rm]").click()
    pg.page.wait_for_timeout(700)
    assert len(pg.records()) == 1 and pg.page.locator("#libRows tr").count() == 1
    pg.go("#/")
    assert pg.page.locator(".card h2", has_text="cve-reference-app").count() >= 1


def test_library_survives_a_reload(pg):
    pg.import_file(REF, check=False)
    pg.go("#/")
    assert pg.page.locator(".badge", has_text="imported").count() >= 1
    pg.page.reload()
    pg.page.wait_for_timeout(800)
    assert pg.page.locator(".badge", has_text="imported").count() >= 1 and len(pg.records()) == 1


def test_sbom_tab_downloads_the_file_that_was_imported(pg):
    pg.import_file(REF, check=False)
    pid = pg.records()[0]["id"]
    pg.go(f"#/p/{pid}/imported/sbom")
    pg.page.wait_for_timeout(500)
    with pg.page.expect_download() as d:
        pg.page.click("#sbGo")
    path = d.value.path()
    assert pathlib.Path(path).read_bytes() == REF.read_bytes() and d.value.suggested_filename == "reference.cdx.json"


def test_failed_check_keeps_the_old_data_and_says_why(browser, site):
    p = Page(browser, site)
    try:
        p.import_file(REF, check=True)
        before = p.records()[0]
        assert before["vuln_total"] == 1
        p.kev_status = 503                                                                  # the KEV list becomes unreachable
        p.go("#/library")
        p.page.locator("button[data-act=check]").first.click()
        p.page.wait_for_timeout(1500)
        msg = p.page.inner_text("#libMsg")
        assert "Check failed, old data kept" in msg and "KEV" in msg and "503" in msg
        after = p.records()[0]
        assert after["vuln_total"] == 1 and after["checkedAt"] == before["checkedAt"] and "503" in after["lastError"]      # data and date untouched, reason recorded
        assert p.errors == []
    finally:
        p.close()


def test_auto_update_refreshes_only_stale_entries_that_were_checked_before(browser, site):
    p = Page(browser, site)
    try:
        p.import_file(REF, check=True)
        p.import_file(REF, check=False)
        checked, unchecked = sorted(p.records(), key=lambda r: r["id"])
        assert checked["checkedAt"] and unchecked["checkedAt"] is None
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        p.set_checked_at(checked["id"], old)
        p.calls.clear()
        p.fresh("#/")                                                                        # opening the Explorer triggers the auto-update
        p.page.wait_for_timeout(4500)
        recs = {r["id"]: r for r in p.records()}
        assert recs[checked["id"]]["checkedAt"] > old and len(p.osv_calls()) >= 2             # the stale, previously checked one was looked up again
        assert recs[unchecked["id"]]["checkedAt"] is None                                     # the never-checked one was left alone
        assert p.errors == []
    finally:
        p.close()


def test_auto_update_off_leaves_stale_entries_alone(browser, site):
    p = Page(browser, site)
    try:
        p.import_file(REF, check=True)
        rid = p.records()[0]["id"]
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        p.set_checked_at(rid, old)
        p.go("#/library")
        p.page.uncheck("#libAuto")
        p.calls.clear()
        p.fresh("#/")
        p.page.wait_for_timeout(3500)
        assert p.records()[0]["checkedAt"] == old and p.osv_calls() == []
        p.go("#/library")
        assert "stale" in p.page.locator("#libRows tr").first.inner_text()                   # and the library says so
        assert p.page.locator("#libStale").is_enabled()
        p.go(f"#/p/{rid}/imported/overview")
        assert "days old" in p.page.inner_text("#app")
    finally:
        p.close()


def test_a_failing_entry_is_not_retried_in_a_loop(browser, site):
    p = Page(browser, site, kev_status=503)
    try:
        p.import_file(REF, check=False)
        rid = p.records()[0]["id"]
        p.go("#/library")
        p.page.locator("button[data-act=check]").first.click()
        p.page.wait_for_timeout(1500)
        assert "503" in p.records()[0]["lastError"]
        p.set_checked_at(rid, (datetime.now(timezone.utc) - timedelta(days=30)).isoformat())  # now it looks stale and checked
        p.page.evaluate("""() => new Promise(res => { const r = indexedDB.open('sbom-explorer-library'); r.onsuccess = () => { const tx = r.result.transaction('sboms','readwrite'), st = tx.objectStore('sboms');
            st.get('local-cve-reference-app').onsuccess = e => { const x = e.target.result; x.lastTry = new Date().toISOString(); st.put(x); }; tx.oncomplete = res; }; })""")
        p.calls.clear()
        p.fresh("#/")
        p.page.wait_for_timeout(3000)
        assert p.osv_calls() == []                                                            # tried a minute ago and failed: not hammered again
    finally:
        p.close()


def test_import_works_without_indexeddb_and_says_so(browser, site):
    ctx = browser.new_context()
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.add_init_script(INIT + ";Object.defineProperty(window,'indexedDB',{value:undefined});")
    page.goto(site + "#/library")
    page.wait_for_timeout(800)
    assert "does not allow local storage" in page.inner_text("#app") and errors == []
    page.goto(site + "#/")
    page.wait_for_timeout(500)
    assert "cve-reference-app" in page.inner_text("#app")                                    # the built-in products are unaffected
    ctx.close()


@pytest.mark.network
def test_against_the_real_services(browser, site):
    ctx = browser.new_context(viewport={"width": 1300, "height": 1000})
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.add_init_script(INIT)
    page.goto(site + "#/library")
    page.wait_for_timeout(500)
    page.set_input_files("#libFile", str(REF))
    page.wait_for_function("document.querySelector('#libMsg') && /Checked|failed|imported/.test(document.querySelector('#libMsg').textContent)", timeout=120000)
    page.wait_for_timeout(1500)
    row = page.locator("#libRows tr").first.inner_text()
    assert "CVE" in row and "KEV ×" in row and "not checked" not in row, row                 # real OSV, KEV mirror, EPSS and PoC answered
    pid = "local-cve-reference-app"
    page.goto(site + f"#/p/{pid}/imported/ir")
    page.wait_for_timeout(1000)
    page.select_option("#irFilter", "kev")
    cves = [r.split("\t")[1] for r in page.locator("#irBody tr").all_inner_texts()]
    assert "CVE-2021-44228" in cves                                                           # Log4Shell is in the real CISA list
    assert errors == []
    ctx.close()
