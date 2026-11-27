#!/usr/bin/env python3
"""Golden-number tests: the safety net for the database work (see tests/golden/README.md).

    python3 tests/golden/golden.py capture            make the fixture from the demo (once; network needed)
    python3 tests/golden/golden.py check  [--update]  both sites in the browser, no server: numbers vs expected/pages-demo.json
    python3 tests/golden/golden.py server URL [--update] [--user U --password P]
                                                      load the fixture into a CyberView server (ALL ITS DATA IS REPLACED:
                                                      a throwaway test stack only), check the API gives the data back
                                                      unchanged, then both sites signed in vs expected/pages-server.json

The clock is frozen at 27 Nov 2026 12:00 UTC and the outside world (EPSS, CISA KEV, endoflife.date) is replayed from
fixture/net.json, so the same code always gives the same numbers. Exit code 0 = everything matches.
"""
import argparse
import asyncio
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from browser import FROZEN_MS, Browser, StaticServer, here, repo_root  # noqa: E402

PROBE = open(here("probe.js"), encoding="utf-8").read()
FIXTURE, NET = here("fixture", "estate.json"), here("fixture", "net.json")


def dump(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def flat(o, p=""):
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            out.update(flat(v, f"{p}.{k}" if p else str(k)))
        return out
    if isinstance(o, list):
        out = {}
        for i, v in enumerate(o):
            out.update(flat(v, f"{p}[{i}]"))
        if not o:
            out[p] = []
        return out
    return {p: o}


def compare(name, got, path, update):
    if update or not os.path.exists(path):
        dump(path, got)
        print(f"  {name}: expected numbers written to {os.path.relpath(path, repo_root())}")
        return True
    want = load(path)
    a, b = flat(want), flat(got)
    diffs = [k for k in sorted(set(a) | set(b)) if a.get(k, "<missing>") != b.get(k, "<missing>")]
    if not diffs:
        print(f"  PASS {name}: {len(a)} numbers match")
        return True
    import tempfile
    gotp = os.path.join(tempfile.gettempdir(), "golden-" + os.path.basename(path).replace(".json", ".got.json"))
    dump(gotp, got)
    print(f"  FAIL {name}: {len(diffs)} of {len(a)} numbers differ (what was found: {gotp})")
    for k in diffs[:40]:
        print(f"     {k}: expected {a.get(k, '<missing>')!r}, got {b.get(k, '<missing>')!r}")
    if len(diffs) > 40:
        print(f"     … and {len(diffs) - 40} more")
    return False


# ------------------------------------------------------------------ capture: the demo, frozen, becomes the fixture
async def capture():
    net = {}
    with StaticServer(repo_root()) as base:
        async with Browser(net=net, mode="record") as b:
            await b.goto(base + "/?demo", 2)
            await b.wait_for("window.app && StorageService.live().length > 100 && Epss.ready", 180)
            await b.js("app.switchView('eol')")             # end-of-life dates are fetched for the EOL report
            await asyncio.sleep(8)
            await b.wait_for("Epss.ready && Epss._kevDone", 60)
            data = await b.js("""(async () => {
                const ls = {}; for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k.startsWith(Demo.NS)) ls[k] = localStorage.getItem(k); }
                return { localStorage: ls, detections: await VulnStore.all('detections'), qids: await VulnStore.all('qids') };
            })()""")
            if b.errors:
                print("page errors while capturing:", *b.errors[:5], sep="\n  ")
    # only the CVEs the fixture has: the CISA KEV catalogue is big, the app looks up by CVE only
    cves = {str(c.get("id") if isinstance(c, dict) else c).upper() for q in data["qids"] for c in (q.get("cves") or [])}
    for url, r in net.items():
        if "kev" in url.lower() and r["body"].lstrip().startswith("{"):
            j = json.loads(r["body"])
            if isinstance(j.get("vulnerabilities"), list):
                j["vulnerabilities"] = [v for v in j["vulnerabilities"] if str(v.get("cveID", "")).upper() in cves]
                j["count"] = len(j["vulnerabilities"])
                r["body"] = json.dumps(j, separators=(",", ":"))
    data["capturedAt"] = "2026-11-27T12:00:00Z (frozen clock)"
    dump(FIXTURE, data)
    dump(NET, net)
    print(f"fixture: {len(data['localStorage'])} stored collections, {len(data['detections'])} findings, {len(data['qids'])} QIDs; {len(net)} recorded outside answers")


# ------------------------------------------------------------------ the browser probes
async def probe_pages(b, base, demo):
    q = "?demo" if demo else ""
    await b.goto(f"{base}/{q}", 2)
    await b.wait_for("window.app && StorageService.live().length > 0 && Epss.ready", 180)
    await asyncio.sleep(1)
    await b.js(PROBE)
    classic = await b.js("goldenClassic()", 300)
    b.local.clear()
    await b.goto(f"{base}/new/{q}", 2)
    await b.wait_for("window.app && typeof UI !== 'undefined' && UI.saved && UI.data && Epss.ready", 180)
    await asyncio.sleep(1)
    await b.js(PROBE)
    new = await b.js("goldenNew()", 300)
    b.new_requests = list(b.local)
    b.new_source = await b.js("UI.q.state")
    return {"classic": classic, "new": new}


async def check(update):
    net = load(NET)
    with StaticServer(repo_root()) as base:
        async with Browser(net=net) as b:
            await b.goto(base + "/tests/golden/loader.html?demo&golden", 1)
            await b.wait_for("window.__loaded", 120)
            info = await b.js("window.__loaded")
            if "error" in info:
                raise SystemExit("could not load the fixture: " + info["error"])
            got = await probe_pages(b, base, demo=True)
            errors = b.errors
            refused = sorted(u for u in b.refused if not u.startswith(("https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com", "https://fonts.g")))     # styling and CSV import only
    ok = compare("both sites, no server (demo mode)", got, here("expected", "pages-demo.json"), update)
    if errors:
        print("  page errors:", *errors[:8], sep="\n    ")
    if refused:
        print("  outside requests not in the recording (refused):", *refused[:8], sep="\n    ")
    return ok and not errors


# ------------------------------------------------------------------ server: load the fixture, check the API round trip, then the pages
class Api:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()), urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))

    def call(self, method, path, body=None):
        req = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(), method=method,
                                     headers={"Content-Type": "application/json", "X-Requested-With": "portal"})
        try:
            with self.op.open(req, timeout=300) as r:
                b = r.read()
                return r.status, (json.loads(b) if b else None)
        except urllib.error.HTTPError as e:
            b = e.read()
            try:
                return e.code, json.loads(b)
            except ValueError:
                return e.code, b.decode("utf-8", "replace")


def client_keys():
    """The page's backup field -> collection name (StorageService.BACKUP_KEYS + KEYS), read from app.js."""
    import re
    src = open(os.path.join(repo_root(), "app.js"), encoding="utf-8").read()
    keys = dict(re.findall(r"^\s+([A-Z_]+): '(gov_[a-z_]+)',", src, re.M))
    back = dict(re.findall(r"(\w+): '([A-Z_]+)'", re.search(r"static BACKUP_KEYS = \{(.*?)\};", src).group(1)))
    return {field: keys[k] for field, k in back.items() if k in keys}


async def server(url, update, user, password):
    F = load(FIXTURE)
    api = Api(url)
    st, me = api.call("GET", "/api/whoami")
    if st == 200 and me.get("open"):
        st, r = api.call("POST", "/api/users", {"username": user, "password": password, "role": "admin"})
        if st != 200:
            raise SystemExit(f"could not create the first administrator: {st} {r}")
    st, r = api.call("POST", "/api/login", {"username": user, "password": password})
    if st != 200:
        raise SystemExit(f"could not sign in as {user}: {st} {r}")
    # the fixture's collections under the page's backup names, the findings in vulnStore: exactly what a backup restore sends
    ns = "acme."
    field_of = {v: k for k, v in client_keys().items()}
    body, sent = {}, {}
    for k, v in F["localStorage"].items():
        name = k[len(ns):]
        if name in field_of:
            body[field_of[name]] = json.loads(v)
            sent[name] = body[field_of[name]]
    body["vulnStore"] = {"detections": F["detections"], "qids": F["qids"]}
    st, r = api.call("POST", "/api/restore", body)
    if st != 200:
        raise SystemExit(f"restore refused: {st} {r}")
    print(f"  loaded the fixture: {len(sent)} collections, {len(F['detections'])} findings, {len(F['qids'])} QIDs")
    # v4.45.1: no CISA KEV list on the server yet -> no server answers (the new site then works the old way)
    st, r = api.call("GET", "/api/q/summary?team=ALL")
    nokev = st == 503 and "KEV" in json.dumps(r)
    print(f"  {'PASS' if nokev else 'FAIL'} without the CISA KEV list the server gives no answers ({st})")
    ok_kev = nokev
    net = load(NET)
    kevcat = next((json.loads(v["body"]) for u, v in net.items() if "kev" in u.lower()), None)
    ep = {}
    for u, v in net.items():
        if "api.first.org" in u:
            for d in json.loads(v["body"]).get("data") or []:
                ep[d["cve"]] = {"epss": float(d["epss"]), "pct": float(d.get("percentile") or 0)}
    st, r = api.call("POST", "/api/admin/intel", {"kev": kevcat, "epss": ep})
    if st != 200:
        raise SystemExit(f"could not load KEV/EPSS into the server: {st} {r}")
    print(f"  loaded the recorded outside data into the server: {r.get('kev')} KEV CVEs, {r.get('epss')} EPSS scores")
    ok = bool(ok_kev)
    # v4.42 stage 1: the relational tables, rebuilt from the fixture, hold exactly the same (every document and column checked)
    want = {"assets": len(sent.get("gov_asset_register", [])), "findings": len(F["detections"]), "vulns": len(F["qids"]), "tasks": len(sent.get("gov_remediation", [])),
            "notes": len(sent.get("gov_asset_notes", [])), "risk_acceptances": len(sent.get("gov_risk_acceptances", [])), "review_queue": len(sent.get("gov_review_queue", []))}
    st, rb = api.call("POST", "/api/admin/relational/rebuild")
    rel_ok = st == 200 and rb.get("verify", {}).get("ok") and all(rb["build"]["counts"].get(k) == v for k, v in want.items())
    print(f"  {'PASS' if rel_ok else 'FAIL'} relational tables rebuilt from the fixture and verified ({', '.join(f'{k} {v}' for k, v in want.items())})")
    if not rel_ok:
        print("     ", json.dumps(rb)[:1500])
    for c in (rb.get("verify", {}).get("checks", []) if isinstance(rb, dict) else []):
        if not c["ok"]:
            print(f"      ✗ {c['name']} {c['detail']}")
    ok &= bool(rel_ok)
    # API round trip: what goes in comes back out unchanged (the contract stage 2 must keep)
    st, state = api.call("GET", "/api/state")
    bad = [n for n, v in sent.items() if state.get(n, {}).get("data") != v]
    print(f"  {'PASS' if not bad else 'FAIL'} /api/state gives back every collection unchanged{': ' + ', '.join(bad) if bad else ''} ({len(sent)} collections)")
    ok &= not bad
    st, dets = api.call("GET", "/api/vuln/detections")
    st2, qids = api.call("GET", "/api/vuln/qids")
    same_d = sorted(json.dumps(d, sort_keys=True) for d in dets) == sorted(json.dumps(d, sort_keys=True) for d in F["detections"])
    same_q = sorted(json.dumps(q, sort_keys=True) for q in qids) == sorted(json.dumps(q, sort_keys=True) for q in F["qids"])
    print(f"  {'PASS' if same_d else 'FAIL'} /api/vuln/detections gives back all {len(F['detections'])} findings unchanged")
    print(f"  {'PASS' if same_q else 'FAIL'} /api/vuln/qids gives back all {len(F['qids'])} QIDs unchanged")
    ok &= same_d and same_q
    # a whole-collection save (how the classic page saves) and the change history it writes
    reg = state["gov_asset_register"]["data"]
    edited = [dict(r) for r in reg]
    edited[0]["service"] = "Golden test"
    st, r = api.call("PUT", "/api/collections/gov_asset_register", {"data": edited, "baseRevision": state["gov_asset_register"]["revision"]})
    st2, again = api.call("GET", "/api/state")
    saved_ok = st == 200 and again["gov_asset_register"]["data"] == edited and again["gov_asset_register"]["revision"] == state["gov_asset_register"]["revision"] + 1
    st3, hist = api.call("GET", "/api/history?record=" + urllib.request.quote(edited[0]["normalizedName"]))
    logged = st3 == 200 and any("Golden test" in json.dumps(h) for h in (hist if isinstance(hist, list) else hist.get("rows", [])))
    st4, stale = api.call("PUT", "/api/collections/gov_asset_register", {"data": reg, "baseRevision": state["gov_asset_register"]["revision"]})
    print(f"  {'PASS' if saved_ok else 'FAIL'} a whole-register save is stored and its revision goes up by one")
    print(f"  {'PASS' if logged else 'FAIL'} the change is in the history")
    print(f"  {'PASS' if st4 == 409 else 'FAIL'} a save from an out-of-date copy is refused (409, got {st4})")
    ok &= saved_ok and logged and st4 == 409
    st8, vf = api.call("POST", "/api/admin/relational/verify")
    kept = st8 == 200 and vf.get("ok") and vf.get("reads") == "relational"
    print(f"  {'PASS' if kept else 'FAIL'} the relational tables kept in step with the saves (verified without a rebuild), reads from them")
    if not kept:
        print("     ", json.dumps(vf)[:1500])
    ok &= bool(kept)
    st5, rb2 = api.call("POST", "/api/admin/relational/rebuild")
    st6, rel = api.call("GET", "/api/admin/relational")
    follows = st5 == 200 and rb2["verify"]["ok"] and st6 == 200 and rel.get("verify", {}).get("ok")
    print(f"  {'PASS' if follows else 'FAIL'} a rebuild after the save picks up the edit and still verifies")
    ok &= bool(follows)
    st7, _ = Api(url).call("POST", "/api/admin/relational/rebuild")
    print(f"  {'PASS' if st7 in (401, 403) else 'FAIL'} the rebuild is refused without signing in ({st7})")
    ok &= st7 in (401, 403)
    api.call("PUT", "/api/collections/gov_asset_register", {"data": reg, "baseRevision": again["gov_asset_register"]["revision"]})     # put it back
    # both sites, signed in, from the server's data
    net = load(NET)
    async with Browser(net=net) as b:
        await b.goto(url.rstrip("/") + "/api/health", 0.5)
        st = await b.js(f"fetch('/api/login', {{ method: 'POST', headers: {{ 'Content-Type': 'application/json', 'X-Requested-With': 'portal' }}, body: JSON.stringify({{ username: {json.dumps(user)}, password: {json.dumps(password)} }}) }}).then(r => r.status)")
        if st != 200:
            raise SystemExit(f"browser sign-in failed: {st}")
        got = await probe_pages(b, url.rstrip("/"), demo=False)
        # v4.45 stage 4: the new site took its numbers from the server's answers, without the whole download
        whole = [u for u in b.new_requests if "/api/vuln/detections" in u]
        asked = [u for u in b.new_requests if "/api/q/findings" in u]
        q_ok = b.new_source == "on" and asked and not whole
        print(f"  {'PASS' if q_ok else 'FAIL'} the new site used the server's answers ({len(asked)} team requests) and never downloaded every finding{' (it did: ' + str(len(whole)) + ')' if whole else ''} [source: {b.new_source}]")
        ok &= bool(q_ok)
        # v4.44 stage 3: the server's rules against the browser's, finding by finding, for every team
        await b.goto(url.rstrip("/") + "/", 2)
        await b.wait_for("window.app && StorageService.live().length > 0 && Epss.ready && Epss._kevDone", 180)
        await b.js(PROBE)
        teams = ["ALL"] + await b.js("OrgSettings.teams()")
        bvec = await b.js(f"goldenVectors({json.dumps(teams)})", 300)
        bconst = await b.js("goldenConstants()")
        errors = b.errors
    st, sconst = api.call("GET", "/api/q/rules")
    same_c = st == 200 and sconst == bconst
    print(f"  {'PASS' if same_c else 'FAIL'} the server's rule constants are the browser's (exploited tags, QVS bands, status defaults, SLA days)")
    if not same_c:
        print("     server:", json.dumps(sconst)[:600]); print("     browser:", json.dumps(bconst)[:600])
    ok &= same_c
    for t in teams:
        st, svec = api.call("GET", f"/api/q/vectors?team={urllib.request.quote(t)}&at={FROZEN_MS}")
        same = st == 200 and svec == bvec[t]
        print(f"  {'PASS' if same else 'FAIL'} server rules = browser rules for {t}: {len(bvec[t])} findings (tier, priority, due, backlog, overdue, exploited)")
        if not same:
            sb, ss = set(bvec[t]), set(svec if isinstance(svec, list) else [])
            for x in sorted(sb - ss)[:6]:
                print("       browser:", x)
            for x in sorted(ss - sb)[:6]:
                print("       server: ", x)
        ok &= same
        st, sm = api.call("GET", f"/api/q/summary?team={urllib.request.quote(t)}&at={FROZEN_MS}")
        tn = got["classic"]["teams"][t]
        keys = ["findings", "machines", "byP", "byTier", "overdue", "backlog", "exploited", "fixes"]
        diff = [k for k in keys if st != 200 or sm.get(k) != tn.get(k)]
        print(f"  {'PASS' if not diff else 'FAIL'} server summary = the classic site's numbers for {t}{': ' + ', '.join(f'{k} {tn.get(k)} vs {sm.get(k)}' for k in diff) if diff else ''}")
        ok &= not diff
    st, wl = api.call("GET", f"/api/q/worklist?team=ALL&at={FROZEN_MS}")
    wl_ok = st == 200 and wl["fixes"] == got["classic"]["teams"]["ALL"]["fixes"] and sum(r["findings"] for r in wl["rows"]) == got["classic"]["teams"]["ALL"]["findings"]
    print(f"  {'PASS' if wl_ok else 'FAIL'} server work list: {wl.get('fixes') if isinstance(wl, dict) else st} fixes covering every finding")
    ok &= wl_ok
    ok &= compare("both sites, signed in to the server", got, here("expected", "pages-server.json"), update)
    if errors:
        print("  page errors:", *errors[:8], sep="\n    ")
    return ok and not errors


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("what", choices=["capture", "check", "server"])
    ap.add_argument("url", nargs="?")
    ap.add_argument("--update", action="store_true", help="write the current numbers as the expected ones")
    ap.add_argument("--user", default="golden")
    ap.add_argument("--password", default="golden-test-password")
    ap.add_argument("--force", action="store_true", help="allow a server that is not on this machine (its data is replaced)")
    a = ap.parse_args()
    if a.what == "capture":
        asyncio.run(capture()); return
    if a.what == "check":
        print("Golden numbers, no server:")
        ok = asyncio.run(check(a.update))
    else:
        if not a.url:
            ap.error("server needs the URL of a throwaway CyberView stack, e.g. https://127.0.0.1:18943")
        from urllib.parse import urlparse
        if urlparse(a.url).hostname not in ("127.0.0.1", "localhost") and not a.force:
            ap.error("this replaces ALL data on that server: only a local throwaway stack (127.0.0.1) unless --force")
        print(f"Golden numbers, server {a.url} (its data is replaced by the fixture):")
        ok = asyncio.run(server(a.url, a.update, a.user, a.password))
    print("all match" if ok else "SOME NUMBERS CHANGED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
