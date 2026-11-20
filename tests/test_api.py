"""API checks against a RUNNING stack that has NO USERS yet (setup mode):  python3 tests/test_api.py [http://127.0.0.1]
It clears the data and creates test users, so only run it on a test stack. Afterwards remove the users again:
  docker compose exec -T db mariadb qualys -e "DELETE FROM users"
"""
import http.cookiejar
import json
import ssl
import sys
import threading
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1").rstrip("/")
fails = []


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        # the stack's certificate is self-signed: do not verify it (test stacks only)
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))

    def call(self, method, path, body=None, csrf=True, raw=False):
        data = None if body is None else json.dumps(body).encode()
        h = {"Content-Type": "application/json"}
        if csrf:
            h["X-Requested-With"] = "portal"
        req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
        try:
            with self.op.open(req, timeout=120) as r:
                b = r.read()
                return r.status, (b if raw else (json.loads(b) if b else None))
        except urllib.error.HTTPError as e:
            b = e.read()
            try:
                return e.code, json.loads(b)
            except ValueError:
                return e.code, b


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  " + str(extra)[:300]))
    if not cond:
        fails.append(name)


anon = Client()
st, h = anon.call("GET", "/api/health")
check("health", st == 200 and h["ok"], h)
st, me = anon.call("GET", "/api/whoami")
check("setup mode: open, administrator", st == 200 and me["open"] and me["role"] == "admin", (st, me))
if not (st == 200 and me["open"]):
    print("This stack already has users; remove them first (see the top of this file).")
    sys.exit(2)

# ---------------------------------------------------------------- data API (as the setup-mode administrator)
a = anon
a.call("POST", "/api/restore", {})           # start from an empty database (this is a test stack)
for k in ["gov_asset_register", "gov_review_queue", "gov_vuln_meta", "gov_risk_acceptances", "gov_remediation", "gov_remediation_settings", "gov_eol_dates"]:
    a.call("DELETE", "/api/collections/" + k)
a.call("DELETE", "/api/vuln")
check("empty state", a.call("GET", "/api/state")[1] == {})
check("write without the anti-forgery header refused", a.call("PUT", "/api/collections/gov_vuln_meta", {"data": {}}, csrf=False)[0] == 403)

reg = [{"normalizedName": f"host-{i}", "owner": "Zoë ☃", "n": i} for i in range(1200)]
st, r = a.call("PUT", "/api/collections/gov_asset_register", {"baseRevision": 0, "data": reg})
check("put array", st == 200 and r["revision"] == 1, r)
st, state = a.call("GET", "/api/state")
check("array round trip", state["gov_asset_register"]["data"] == reg)
meta = {"imports": [{"file": "a.csv", "rows": 5}], "truncated": False}
a.call("PUT", "/api/collections/gov_vuln_meta", {"baseRevision": 0, "data": meta})
check("object round trip", a.call("GET", "/api/state")[1]["gov_vuln_meta"]["data"] == meta)
st, r = a.call("PUT", "/api/collections/gov_asset_register", {"baseRevision": 1, "data": reg[:10]})
check("second save ok", st == 200 and r["revision"] == 2)
st, r = a.call("PUT", "/api/collections/gov_asset_register", {"baseRevision": 1, "data": reg[:5]})
check("stale save refused with 409", st == 409 and r["conflict"], (st, r))
check("unknown collection", a.call("PUT", "/api/collections/evil", {"data": []})[0] == 404)
check("bad payload", a.call("PUT", "/api/collections/gov_asset_register", {"data": 5})[0] == 400)

dets = [{"k": f"a{i % 3}|{q}|tcp|{q}", "asset": f"a{i % 3}", "qid": str(q), "proto": "tcp", "port": str(q), "sev": 3, "qvs": q * 1.5} for i, q in enumerate(range(1, 301))]
a.call("POST", "/api/vuln/merge", {"clearAll": True, "detections": dets[:100], "qids": []})
a.call("POST", "/api/vuln/merge", {"detections": dets[100:], "qids": [{"qid": str(q), "title": f"T{q} ü"} for q in range(1, 301)]})
st, got = a.call("GET", "/api/vuln/detections")
check("detections round trip", st == 200 and len(got) == 300)
a.call("POST", "/api/vuln/merge", {"assets": ["a0"], "detections": [{"k": "a0|999|tcp|1", "asset": "a0", "qid": "999", "sev": 5, "qvs": 99}]})
got = a.call("GET", "/api/vuln/detections")[1]
check("replace by asset", len([d for d in got if d["asset"] == "a0"]) == 1 and len(got) == 201, len(got))

# ---------------------------------------------------------------- first administrator
st, r = anon.call("POST", "/api/users", {"username": "bad name!", "password": "x" * 12, "role": "admin"})
check("bad user name refused", st == 400, (st, r))
st, r = anon.call("POST", "/api/users", {"username": "root1", "password": "short", "role": "admin"})
check("short password refused", st == 400, (st, r))
admin = anon
st, r = admin.call("POST", "/api/users", {"username": "root1", "password": "correct horse 1", "role": "viewer"})
check("first user is made administrator and signed in", st == 200 and r["firstUser"], (st, r))
st, me = admin.call("GET", "/api/whoami")
check("whoami after first user", me["user"] == "root1" and me["role"] == "admin" and not me["open"], me)
nobody = Client()
check("no session: api -> 401", nobody.call("GET", "/api/state")[0] == 401)
st, page = nobody.call("GET", "/", raw=True)
check("no session: page is the login form", st == 200 and b"Sign in" in page and b"api/login" in page)
check("health stays open", nobody.call("GET", "/api/health")[0] == 200)

# ---------------------------------------------------------------- roles
for name, role, must in [("ed1", "editor", False), ("view1", "viewer", False), ("temp1", "editor", True)]:
    st, r = admin.call("POST", "/api/users", {"username": name, "password": "password-" + name, "role": role, "mustChange": must})
    check(f"admin adds {name}", st == 200, (st, r))
check("duplicate user refused", admin.call("POST", "/api/users", {"username": "ED1", "password": "password-xxxxx", "role": "editor"})[0] == 409)


def sign_in(name, pw):
    c = Client()
    st, r = c.call("POST", "/api/login", {"username": name, "password": pw})
    return c, st, r


ed, st, r = sign_in("ed1", "password-ed1")
check("editor signs in", st == 200 and r["role"] == "editor", (st, r))
vw, st, r = sign_in("view1", "password-view1")
check("viewer signs in", st == 200)
check("viewer can read", vw.call("GET", "/api/state")[0] == 200 and vw.call("GET", "/api/vuln/detections")[0] == 200)
check("viewer cannot save", vw.call("PUT", "/api/collections/gov_vuln_meta", {"baseRevision": None, "data": {}})[0] == 403)
check("viewer cannot import vulns", vw.call("POST", "/api/vuln/merge", {"detections": []})[0] == 403)
check("viewer can see history", vw.call("GET", "/api/history")[0] == 200)
check("viewer cannot see activity", vw.call("GET", "/api/audit")[0] == 403)
check("editor can save", ed.call("PUT", "/api/collections/gov_vuln_meta", {"baseRevision": None, "data": {"by": "ed1"}})[0] == 200)
check("editor can import vulns", ed.call("POST", "/api/vuln/merge", {"detections": []})[0] == 200)
check("editor cannot delete data", ed.call("DELETE", "/api/collections/gov_vuln_meta")[0] == 403 and ed.call("DELETE", "/api/vuln")[0] == 403)
check("editor cannot restore", ed.call("POST", "/api/restore", {})[0] == 403)
check("editor cannot manage users", ed.call("GET", "/api/users")[0] == 403 and ed.call("POST", "/api/users", {"username": "zz", "password": "password-zz1", "role": "admin"})[0] == 403)
check("editor cannot see activity", ed.call("GET", "/api/audit")[0] == 403)

# must change password first
tp, st, r = sign_in("temp1", "password-temp1")
check("temp user signs in, flagged", st == 200 and r["mustChange"], r)
check("blocked until password changed", tp.call("GET", "/api/state")[0] == 403)
check("wrong current password refused", tp.call("POST", "/api/me/password", {"current": "nope", "new": "a brand new password"})[0] == 400)
check("password change works", tp.call("POST", "/api/me/password", {"current": "password-temp1", "new": "a brand new password"})[0] == 200)
check("then allowed", tp.call("GET", "/api/state")[0] == 200)
check("old password no longer works", sign_in("temp1", "password-temp1")[1] == 401)

# ---------------------------------------------------------------- change history
ed.call("PUT", "/api/collections/gov_asset_register", {"baseRevision": None, "data": [dict(reg[0], owner="Platform"), reg[1], {"normalizedName": "brand-new", "owner": "CORP"}]})
st, hist = admin.call("GET", "/api/history?record=host-0")
ch = [h for h in hist if h["record"] == "host-0" and h["action"] == "change"]
check("history records who changed the owner", ch and ch[0]["user"] == "ed1" and ch[0]["changes"]["owner"]["to"] == "Platform", hist[:3])
st, hist = admin.call("GET", "/api/history?user=ed1&collection=gov_asset_register")
check("history: added and removed", {h["action"] for h in hist} >= {"add", "change", "remove"}, [h["action"] for h in hist])
big = [{"normalizedName": f"b{i}"} for i in range(700)]
ed.call("PUT", "/api/collections/gov_asset_register", {"baseRevision": None, "data": big})
hist = admin.call("GET", "/api/history?limit=3")[1]
check("big change is one summary line", hist[0]["action"] == "bulk" and hist[0]["changes"]["add"] == 700, hist[0])

# ---------------------------------------------------------------- user management rules
st, r = admin.call("PATCH", "/api/users/root1", {"role": "viewer"})
check("cannot change own role", st == 400, r)
check("cannot disable self", admin.call("PATCH", "/api/users/root1", {"disabled": True})[0] == 400)
check("cannot delete self", admin.call("DELETE", "/api/users/root1")[0] == 400)
admin.call("PATCH", "/api/users/ed1", {"role": "admin"})
check("promoted editor is cut off until sign-in again", ed.call("GET", "/api/state")[0] == 401)
ed, st, _ = sign_in("ed1", "password-ed1")
check("second admin can manage users", ed.call("GET", "/api/users")[0] == 200)
check("demote a second admin ok", admin.call("PATCH", "/api/users/ed1", {"role": "editor"})[0] == 200)
check("demoted admin's old session is ended", ed.call("GET", "/api/users")[0] == 401)
ed, st, _ = sign_in("ed1", "password-ed1")
check("demoted admin can no longer delete users", ed.call("DELETE", "/api/users/root1")[0] == 403)
check("disable a user ends their session", admin.call("PATCH", "/api/users/view1", {"disabled": True})[0] == 200 and vw.call("GET", "/api/state")[0] == 401)
check("disabled user cannot sign in", sign_in("view1", "password-view1")[1] == 401)
admin.call("PATCH", "/api/users/view1", {"disabled": False})
st, r = admin.call("PATCH", "/api/users/view1", {"password": "reset password 99"})
check("admin resets a password", st == 200)
c, st, r = sign_in("view1", "reset password 99")
check("reset user must change password", st == 200 and r["mustChange"])

# lockout
for i in range(5):
    sign_in("ed1", "wrong-" + str(i))
st, r = sign_in("ed1", "password-ed1")[1:]
check("five wrong passwords lock the account", st == 429, (st, r))
admin.call("PATCH", "/api/users/ed1", {"unlock": True})
check("admin unlocks", sign_in("ed1", "password-ed1")[1] == 200)

# ---------------------------------------------------------------- remediation tasks (v3.8) and EOL dates (v3.5)
admin.call("POST", "/api/users", {"username": "view2", "password": "password-view2", "role": "viewer"})
vw = sign_in("view2", "password-view2")[0]       # the earlier viewer had its password reset above
check("tasks: editor reads people", ed.call("GET", "/api/people")[0] == 200 and "ed1" in [p["username"] for p in ed.call("GET", "/api/people")[1]])
check("tasks: viewer reads people", vw.call("GET", "/api/people")[0] == 200)
check("tasks: whole-collection save refused", ed.call("PUT", "/api/collections/gov_remediation", {"baseRevision": None, "data": []})[0] == 400)
st, r = ed.call("POST", "/api/tasks", {"tasks": [{"type": "vuln", "title": "Patch <b>x</b>", "assets": [{"name": "host-1", "state": "open"}, {"name": "host-2"}], "team": "Platform",
                                                "assignee": "view1", "due": "2026-12-01", "status": "Open", "ticket": "CHG1", "comment": "first", "id": "TASK-9999", "rev": 77,
                                                "source": {"kind": "qid", "key": "123", "qids": ["123"]}}]})
check("tasks: create", st == 200 and r["tasks"][0]["id"] == "TASK-0001" and r["tasks"][0]["rev"] == 1 and r["tasks"][0]["createdBy"] == "ed1", (st, r))
t1 = r["tasks"][0] if st == 200 else {}
check("tasks: server owns id/rev and keeps the first comment", t1.get("comments", [{}])[0].get("text") == "first" and t1.get("comments")[0].get("by") == "ed1", t1)
check("tasks: unknown assignee refused", ed.call("POST", "/api/tasks", {"task": {"title": "x", "assignee": "nobody"}})[0] == 400)
check("tasks: bad status refused", ed.call("POST", "/api/tasks", {"task": {"title": "x", "status": "Done!"}})[0] == 400)
check("tasks: empty title refused", ed.call("POST", "/api/tasks", {"task": {"title": "  "}})[0] == 400)
check("tasks: viewer cannot create", vw.call("POST", "/api/tasks", {"task": {"title": "x"}})[0] == 403)
check("tasks: show up in state", [t["id"] for t in ed.call("GET", "/api/state")[1]["gov_remediation"]["data"]] == ["TASK-0001"])
upd = dict(t1, status="In progress", assets=[{"name": "host-1", "state": "fixed"}, {"name": "host-2", "state": "open"}])
st, r = ed.call("PUT", "/api/tasks/TASK-0001", {"baseRev": 1, "task": upd, "comment": "one done"})
check("tasks: update", st == 200 and r["task"]["rev"] == 2 and r["task"]["status"] == "In progress" and len(r["task"]["comments"]) == 2, (st, r))
st, r = admin.call("PUT", "/api/tasks/TASK-0001", {"baseRev": 1, "task": dict(upd, status="Cancelled")})
check("tasks: stale update refused with 409 and the current copy", st == 409 and r["task"]["rev"] == 2 and r["task"]["status"] == "In progress", (st, r))
st, r = admin.call("POST", "/api/tasks/TASK-0001/comments", {"text": "no revision needed"})
check("tasks: comment without revision", st == 200 and r["task"]["rev"] == 3 and r["task"]["comments"][-1]["by"] == "root1", (st, r))
check("tasks: viewer cannot update", vw.call("PUT", "/api/tasks/TASK-0001", {"baseRev": 3, "task": upd})[0] == 403)
check("tasks: viewer cannot comment", vw.call("POST", "/api/tasks/TASK-0001/comments", {"text": "x"})[0] == 403)
check("tasks: unknown task 404", ed.call("PUT", "/api/tasks/TASK-0404", {"baseRev": 1, "task": upd})[0] == 404)
st, r = ed.call("PUT", "/api/tasks/TASK-0001", {"baseRev": 3, "task": dict(upd, status="Verified")})
check("tasks: closing sets closedAt", st == 200 and r["task"]["closedAt"], r)
# two editors creating at the same moment get different ids
res = []
def mk(c, n):
    res.append(c.call("POST", "/api/tasks", {"task": {"title": "parallel " + n}}))
ths = [threading.Thread(target=mk, args=(c, n)) for c, n in [(ed, "a"), (admin, "b"), (ed, "c"), (admin, "d")] * 3]
[t.start() for t in ths]; [t.join() for t in ths]
ids = [r[1]["tasks"][0]["id"] for r in res if r[0] == 200]
check("tasks: 12 parallel creates all succeed with distinct ids", len(ids) == 12 and len(set(ids)) == 12, [(r[0], r[1].get("tasks", [{}])[0].get("id") if isinstance(r[1], dict) and r[0] == 200 else r[1]) for r in res])
st, hist = admin.call("GET", "/api/history?collection=gov_remediation")
check("tasks: history records add + change", st == 200 and {"add", "change"} <= {h["action"] for h in hist} and any("status" in (h["changes"] or {}) for h in hist), hist[:3])
check("tasks: history leaves out rev/updatedAt noise", all("rev" not in (h["changes"] or {}) and "updatedAt" not in (h["changes"] or {}) for h in hist))
# deadline rules and EOL dates are ordinary collections
check("tasks: save deadline rules", ed.call("PUT", "/api/collections/gov_remediation_settings", {"baseRevision": None, "data": {"sla": {"t1": 7}}})[0] == 200)
check("eol dates: save", ed.call("PUT", "/api/collections/gov_eol_dates", {"baseRevision": None, "data": [{"match": "JUNOS 21", "secEnd": "2027-03-31"}]})[0] == 200)
s3 = ed.call("GET", "/api/state")[1]
check("eol dates + rules come back", s3["gov_eol_dates"]["data"][0]["match"] == "JUNOS 21" and s3["gov_remediation_settings"]["data"]["sla"]["t1"] == 7)
st, r = ed.call("POST", "/api/tasks", {"task": {"title": "checks", "reopened": True, "lastCheck": "scan.csv", "assets": [{"name": "h1", "state": "verified", "note": "not detected in scan.csv",
                                                  "chk": {"qids": ["1", "2"], "os": "Win 2016", "evil": "x"}, "ok": {"qids": True, "os": False, "bad": True}}]}})
a0 = r["tasks"][0]["assets"][0] if st == 200 else {}
check("tasks: per-asset check targets and results are kept (unknown keys dropped)", st == 200 and a0.get("chk") == {"os": "Win 2016", "qids": ["1", "2"]} and a0.get("ok") == {"qids": True, "os": False}
      and r["tasks"][0]["reopened"] is True and r["tasks"][0]["lastCheck"] == "scan.csv", r)
tasks_before = ed.call("GET", "/api/tasks")[1]
check("tasks: list", len(tasks_before) == 14, len(tasks_before))

# ---------------------------------------------------------------- restore (atomic) and activity
a_state = admin.call("GET", "/api/state")[1]
a_dets = admin.call("GET", "/api/vuln/detections")[1]
backup = {"assetRegister": [{"normalizedName": "restored-1", "owner": "Platform"}], "riskAcceptances": [], "vulnMeta": {"imports": []},
          "vulnStore": {"detections": [{"k": "r|1|tcp|1", "asset": "r", "qid": "1", "sev": 5, "qvs": 1}], "qids": [{"qid": "1", "title": "t"}]}}
st, r = admin.call("POST", "/api/restore", backup)
check("restore", st == 200, (st, r))
s2 = admin.call("GET", "/api/state")[1]
check("restore replaced the register", [x["normalizedName"] for x in s2["gov_asset_register"]["data"]] == ["restored-1"] and "gov_review_queue" not in s2, list(s2))
check("restore replaced the detections", [d["asset"] for d in admin.call("GET", "/api/vuln/detections")[1]] == ["r"])
check("restore of a backup without tasks clears them", admin.call("GET", "/api/tasks")[1] == [])
st, r = admin.call("POST", "/api/restore", dict(backup, remediation=tasks_before, remediationSettings={"sla": {"t1": 7}}, eolDates=[{"match": "JUNOS 21", "secEnd": "2027-03-31"}]))
s4 = admin.call("GET", "/api/state")[1]
check("restore brings tasks, rules and EOL dates back", st == 200 and admin.call("GET", "/api/tasks")[1] == tasks_before and s4["gov_eol_dates"]["data"][0]["match"] == "JUNOS 21" and s4["gov_remediation_settings"]["data"]["sla"]["t1"] == 7, (st, list(s4)))
st, r = admin.call("POST", "/api/tasks", {"task": {"title": "after restore"}})
check("tasks: ids continue after restore", st == 200 and r["tasks"][0]["id"] == "TASK-0015", r)
check("reset: admin can delete the task collection", admin.call("DELETE", "/api/collections/gov_remediation")[0] == 200 and admin.call("GET", "/api/tasks")[1] == [])
check("reset: editor cannot", ed.call("DELETE", "/api/collections/gov_remediation")[0] == 403)
st, r = admin.call("POST", "/api/tasks", {"task": {"title": "after reset"}})
check("tasks: first task after reset is TASK-0001 again and is listed in state", st == 200 and r["tasks"][0]["id"] == "TASK-0001" and "gov_remediation" in admin.call("GET", "/api/state")[1], r)
st, act = admin.call("GET", "/api/audit?limit=300")
actions = {x["action"] for x in act}
check("activity log has sign-ins, locks, user changes, restore", {"login", "login-failed", "locked", "user-added", "user-edited", "restore"} <= actions, actions)

# Automox: status for everyone, never the key; sync for editors only; hand links go through backup + restore
admin.call("POST", "/api/users", {"username": "axview", "password": "password-axview", "role": "viewer"})
axv, _, _ = sign_in("axview", "password-axview")
st, ax = axv.call("GET", "/api/automox/status")
check("automox: viewer reads the status", st == 200 and isinstance(ax.get("configured"), bool), (st, ax))
check("automox: status holds no key", "api_key" not in json.dumps(ax).lower() and "apikey" not in json.dumps(ax).lower(), ax)
check("automox: viewer cannot start a sync", axv.call("POST", "/api/automox/sync", {})[0] == 403)
check("automox: viewer reads the data", axv.call("GET", "/api/automox/data")[0] == 200)
if not ax.get("configured"):
    st, r = ed.call("POST", "/api/automox/sync", {})
    check("automox: no key -> sync refused with a setup message", st == 400 and r.get("kind") == "setup", (st, r))
st, r = admin.call("POST", "/api/restore", dict(backup, automoxLinks={"restored-1": "123"}))
check("automox: hand links restored", st == 200 and admin.call("GET", "/api/state")[1]["gov_automox_links"]["data"] == {"restored-1": "123"})

# Qualys API sync: status for everyone, never the login; sync and apply for editors only; one claim per sync
st, qx = axv.call("GET", "/api/qualys/status")
check("qualys: viewer reads the status", st == 200 and isinstance(qx.get("configured"), bool) and "blocked" in qx, (st, qx))
check("qualys: status holds no password", "password" not in json.dumps(qx).lower(), qx)
check("qualys: viewer cannot start a sync", axv.call("POST", "/api/qualys/sync", {})[0] == 403)
check("qualys: viewer cannot claim a sync", axv.call("POST", "/api/qualys/claim", {"syncId": "x"})[0] == 403)
check("qualys: viewer reads the data", axv.call("GET", "/api/qualys/data")[0] == 200)
st, hist = axv.call("GET", "/api/qualys/history")
check("qualys: viewer reads the sync history (a list, no password)", st == 200 and isinstance(hist, list) and "password" not in json.dumps(hist).lower(), (st, hist))
check("qualys: claiming a sync that is not the latest is refused", ed.call("POST", "/api/qualys/claim", {"syncId": "not-a-sync"})[0] == 409)
check("qualys: 'applied' without a claim is refused", ed.call("POST", "/api/qualys/applied", {"syncId": "not-a-sync", "summary": {}})[0] == 409)
if not qx.get("configured"):
    st, r = ed.call("POST", "/api/qualys/sync", {})
    check("qualys: no login -> sync refused with a setup message", st == 400 and r.get("kind") == "setup", (st, r))
elif qx.get("last") and not (qx.get("applied") or {}).get("syncId") == qx["last"]["syncId"]:
    sid = qx["last"]["syncId"]
    st1, _ = ed.call("POST", "/api/qualys/claim", {"syncId": sid})
    st2, _ = admin.call("POST", "/api/qualys/claim", {"syncId": sid})
    check("qualys: a second editor cannot claim a sync being applied", st1 == 200 and st2 == 409, (st1, st2))
elif qx.get("last"):
    check("qualys: an applied sync cannot be claimed again", ed.call("POST", "/api/qualys/claim", {"syncId": qx["last"]["syncId"]})[0] == 409)

# Status rules: administrators only; an editor's page may set the go-live date once, while it is empty
admin.call("PUT", "/api/collections/gov_status_settings", {"data": {}, "baseRevision": None})
st1, _ = ed.call("PUT", "/api/collections/gov_status_settings", {"data": {"goLive": "2026-11-13"}, "baseRevision": None})
check("status rules: editor may set an empty go-live date", st1 == 200, st1)
st2, _ = ed.call("PUT", "/api/collections/gov_status_settings", {"data": {"goLive": "2026-11-13", "internetStep": False}, "baseRevision": None})
check("status rules: editor cannot change a rule", st2 == 403, st2)
st3, _ = ed.call("PUT", "/api/collections/gov_status_settings", {"data": {"goLive": "2026-12-01"}, "baseRevision": None})
check("status rules: editor cannot move a set go-live date", st3 == 403, st3)
st4, _ = admin.call("PUT", "/api/collections/gov_status_settings", {"data": {"goLive": "2026-11-13", "internetStep": False}, "baseRevision": None})
check("status rules: administrator can change them", st4 == 200, st4)

# Organisation setup (v3.20): administrators only; everyone can read it; it is in backups
org = {"teams": ["Team A", "Team B"], "mainTeam": "Team A", "domainSuffixes": [".example.net"], "ownerRules": []}
check("org setup: editor cannot save it", ed.call("PUT", "/api/collections/gov_org_settings", {"data": org, "baseRevision": None})[0] == 403)
check("org setup: viewer cannot save it", vw.call("PUT", "/api/collections/gov_org_settings", {"data": org, "baseRevision": None})[0] == 403)
check("org setup: administrator can save it", admin.call("PUT", "/api/collections/gov_org_settings", {"data": org, "baseRevision": None})[0] == 200)
st, state = vw.call("GET", "/api/state")
check("org setup: everyone can read it", st == 200 and "Team A" in json.dumps(state), st)
st, r = admin.call("POST", "/api/restore", {"assetRegister": [], "orgSettings": dict(org, mainTeam="Team B")})
s5 = admin.call("GET", "/api/state")[1]
check("org setup: a backup brings it back (restore)", st == 200 and s5.get("gov_org_settings", {}).get("data", {}).get("mainTeam") == "Team B", (st, s5.get("gov_org_settings")))

# Comments on machines and findings (v4.26): saved one at a time, stamped with the signed-in user, edits keep the earlier wording
admin.call("POST", "/api/users", {"username": "ed2", "password": "password-ed2", "role": "editor"})
ed2, _, _ = sign_in("ed2", "password-ed2")
st, r = ed.call("POST", "/api/notes", {"asset": "web01.example.net", "text": "Reboots on Sundays only", "by": "someone-else"})
n1 = (r or {}).get("note", {})
check("notes: editor adds a machine comment, stamped with their name (not what the page sent)", st == 200 and n1.get("by") == "ed1" and n1.get("qid") == "" and n1.get("at"), (st, r))
st, r = ed.call("POST", "/api/notes", {"asset": "web01.example.net", "qid": "38170", "text": "Vendor fix due in March"})
n2 = (r or {}).get("note", {})
check("notes: editor adds a finding comment", st == 200 and n2.get("qid") == "38170" and n2.get("id") != n1.get("id"), (st, r))
check("notes: empty text refused", ed.call("POST", "/api/notes", {"asset": "web01.example.net", "text": "  "})[0] == 400)
check("notes: a QID must be a number", ed.call("POST", "/api/notes", {"asset": "web01.example.net", "qid": "x1", "text": "a"})[0] == 400)
check("notes: viewer cannot add", vw.call("POST", "/api/notes", {"asset": "web01.example.net", "text": "hi"})[0] == 403)
check("notes: cannot be saved as a whole collection", ed.call("PUT", "/api/collections/gov_asset_notes", {"data": [], "baseRevision": None})[0] == 400)
st, lst = vw.call("GET", "/api/notes")
check("notes: viewer reads them", st == 200 and {n["id"] for n in lst} >= {n1.get("id"), n2.get("id")}, (st, lst))
check("notes: in /api/state", any(n["id"] == n1.get("id") for n in vw.call("GET", "/api/state")[1].get("gov_asset_notes", {}).get("data", [])))
st, r = ed2.call("PUT", f"/api/notes/{n1.get('id')}", {"text": "Reboots on Sunday mornings only", "baseRev": n1.get("rev")})
e1 = (r or {}).get("note", {})
check("notes: another editor can edit; earlier wording kept", st == 200 and e1.get("editedBy") == "ed2" and e1.get("by") == "ed1" and e1.get("hist", [{}])[0].get("text") == "Reboots on Sundays only" and e1.get("rev") == 2, (st, r))
st, r = ed.call("PUT", f"/api/notes/{n1.get('id')}", {"text": "stale edit", "baseRev": 1})
check("notes: an edit from an old copy gets 409 with the current one", st == 409 and r.get("note", {}).get("text") == "Reboots on Sunday mornings only", (st, r))
check("notes: viewer cannot edit", vw.call("PUT", f"/api/notes/{n1.get('id')}", {"text": "x", "baseRev": 2})[0] == 403)
check("notes: someone else's comment cannot be deleted by an editor", ed2.call("POST", f"/api/notes/{n2.get('id')}/delete")[0] == 403)
st, r = ed.call("POST", f"/api/notes/{n2.get('id')}/delete")
check("notes: the author can delete (kept, marked deleted)", st == 200 and r["note"].get("deleted") is True and r["note"].get("deletedBy") == "ed1", (st, r))
check("notes: a deleted comment cannot be edited", ed.call("PUT", f"/api/notes/{n2.get('id')}", {"text": "x", "baseRev": r["note"]["rev"]})[0] == 404)
check("notes: an administrator can delete anyone's", admin.call("POST", f"/api/notes/{n1.get('id')}/delete")[0] == 200)
acts = [a["action"] for a in admin.call("GET", "/api/audit?limit=50")[1]]
check("notes: activity log has added, edited and deleted", {"comment-added", "comment-edited", "comment-deleted"} <= set(acts), acts[:12])
# parallel adds never lose one
res = []
def add_one(i):
    res.append(ed.call("POST", "/api/notes", {"asset": "db01.example.net", "text": f"parallel {i}"})[0])
th = [threading.Thread(target=add_one, args=(i,)) for i in range(8)]
[t.start() for t in th]; [t.join() for t in th]
ids = [n["id"] for n in vw.call("GET", "/api/notes")[1] if n["text"].startswith("parallel")]
check("notes: 8 parallel adds, 8 comments with different ids", res.count(200) == 8 and len(set(ids)) == 8, (res, ids))
st, r = admin.call("POST", "/api/restore", {"assetRegister": [], "assetNotes": [{"id": "N-000099", "asset": "x", "qid": "", "text": "from backup", "at": "2026-11-01T00:00:00Z", "by": "ed1", "rev": 1}]})
check("notes: a backup brings them back (restore)", st == 200 and [n["text"] for n in vw.call("GET", "/api/notes")[1]] == ["from backup"])
st, r = ed.call("POST", "/api/notes", {"asset": "x", "text": "after restore"})
check("notes: new ids continue after a restore", st == 200 and r["note"]["id"] == "N-000100", r)

# logout ends the session
check("logout", admin.call("POST", "/api/logout")[0] == 200 and admin.call("GET", "/api/state")[0] == 401)
print("\n%d failed" % len(fails) if fails else "\nall passed")
sys.exit(1 if fails else 0)
