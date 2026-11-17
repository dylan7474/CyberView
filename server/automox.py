"""Automox: read-only sync of devices and patch data into the portal's database.

The API key stays on the server (AUTOMOX_API_KEY in .env); the page only ever sees `configured: true/false`.
Only GET requests are made. Automox allows fewer than 30 requests a minute, so calls are spaced out and a sync
runs in a background thread while the page polls /api/automox/status.

Everything Automox returns goes through normalise_device / normalise_package, so if a field name differs from
what we expect there is one place to fix.

    python3 automox.py test      check the key and organisation, fetch one page of devices (prints no secrets)
"""
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BASE = os.environ.get("AUTOMOX_BASE_URL", "https://console.automox.com/api").rstrip("/")
KEY = os.environ.get("AUTOMOX_API_KEY", "").strip()
ORG = os.environ.get("AUTOMOX_ORG_ID", "").strip()
try:
    HOURS = float(os.environ.get("AUTOMOX_SYNC_HOURS", "0") or 0)       # 0 = only when someone presses Sync
except ValueError:
    HOURS = 0
GAP = float(os.environ.get("AUTOMOX_REQUEST_GAP", "2.2"))              # seconds between calls (< 30 a minute)
PAGE = 500
MAX_DEVICE_CALLS = int(os.environ.get("AUTOMOX_MAX_DEVICE_CALLS", "150"))  # per-device package lookups per sync
MAX_PAGES = 400

SCHEMA = """CREATE TABLE IF NOT EXISTS automox (
    kind VARCHAR(10) NOT NULL,
    k VARCHAR(80) NOT NULL,
    doc LONGTEXT NOT NULL,
    PRIMARY KEY (kind, k)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""

_conn_ctx = None
_audit = None


def init(conn_ctx, audit):
    """Called by app.py at startup with its database helpers."""
    global _conn_ctx, _audit
    _conn_ctx, _audit = conn_ctx, audit
    if configured() and HOURS > 0:
        threading.Thread(target=_scheduler, name="automox-schedule", daemon=True).start()


def configured():
    return bool(KEY)


class AxError(Exception):
    """kind: setup | network | auth | forbidden | rate | http | org | data. The message never contains the key."""
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


# ------------------------------------------------------------------ HTTP

_call_lock = threading.Lock()
_last_call = [0.0]
_calls = [0]


def get(path, params=None):
    """One GET against the Automox API, spaced out to stay under the rate limit; retries 429 and 5xx."""
    url = BASE + path + ("?" + urllib.parse.urlencode(params) if params else "")
    for attempt in range(4):
        with _call_lock:
            wait = _last_call[0] + GAP - time.time()
            if wait > 0:
                time.sleep(wait)
            _last_call[0] = time.time()
            _calls[0] += 1
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + KEY, "Accept": "application/json",
                                                   "User-Agent": "governance-portal"})
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                body = r.read()
            try:
                return json.loads(body or b"null")
            except ValueError:
                raise AxError("data", f"Automox sent something that is not JSON for {path}")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise AxError("auth", "Automox refused the API key (401). Check AUTOMOX_API_KEY, or make a new key.")
            if e.code == 404 and path == "/orgs":     # seen 2026-11-12: Automox answers an unknown key with 404 here
                raise AxError("auth", "Automox did not recognise the API key (404 on /orgs). Check AUTOMOX_API_KEY, or make a new key.")
            if e.code == 403:
                raise AxError("forbidden", f"The API key is not allowed to read {path} (403). The Automox user behind the key needs read access.")
            if e.code == 429 and attempt < 3:
                time.sleep(65)                       # Automox blocks for a minute after too many calls
                continue
            if e.code == 429:
                raise AxError("rate", "Automox kept saying 'too many requests' (429). Try again in a few minutes.")
            if e.code >= 500 and attempt < 3:
                time.sleep(5 * (attempt + 1))
                continue
            raise AxError("http", f"Automox answered {e.code} for {path}")
        except urllib.error.URLError as e:
            if attempt < 2:
                time.sleep(5)
                continue
            raise AxError("network", f"Could not reach {urllib.parse.urlsplit(BASE).hostname}: {getattr(e, 'reason', e)}. "
                                     "Check the server can make HTTPS connections out to it (DNS, firewall, proxy).")
        except TimeoutError:
            if attempt < 2:
                continue
            raise AxError("network", f"Automox did not answer in time for {path}")
    raise AxError("http", f"Gave up on {path}")


def rows_of(payload):
    """Automox endpoints return either a bare list or {data: [...]} (or results)."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for k in ("data", "results", "items"):
            if isinstance(payload.get(k), list):
                return payload[k]
    return []


def paged(path, params, progress=None, limit=PAGE):
    """All pages of a list endpoint. Automox gives no totals: a page shorter than the limit is the last one."""
    out = []
    for page in range(MAX_PAGES):
        rows = rows_of(get(path, {**params, "limit": limit, "page": page}))
        out.extend(r for r in rows if isinstance(r, dict))
        if progress:
            progress(len(out))
        if len(rows) < limit:
            return out
    raise AxError("data", f"{path} still had more after {MAX_PAGES} pages; stopped")


# ------------------------------------------------------------------ normalising

def _s(v, n=200):
    return "" if v is None else str(v)[:n]


def _first(d, *keys):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return None


def _list(v):
    if isinstance(v, list):
        return v
    if isinstance(v, str) and v:
        return [x.strip() for x in v.replace(";", ",").split(",") if x.strip()]
    return []


def _bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str) and v.lower() in ("true", "false", "yes", "no", "1", "0"):
        return v.lower() in ("true", "yes", "1")
    return None


def normalise_device(d):
    detail = d.get("detail") if isinstance(d.get("detail"), dict) else {}
    status = d.get("status") if isinstance(d.get("status"), dict) else {}
    ips = []
    for v in (_list(d.get("ip_addrs")) + _list(d.get("ip_addrs_private")) + _list(detail.get("IPS"))):
        v = _s(v, 60).strip()
        if v and v not in ips:
            ips.append(v)
    # status.policy_statuses = [{id, compliant}]; the top-level policy_status list has the names and last run.
    # Seen 2026-11-12: the top-level `compliant` can be true while a patch policy is non-compliant, so the
    # per-policy flags (and status.policy_status "compliant"/"non-compliant") win.
    runs = {}
    for r in (d.get("policy_status") if isinstance(d.get("policy_status"), list) else []):
        if isinstance(r, dict):
            runs[_s(_first(r, "policy_id", "id"), 20)] = r
    flags = status.get("policy_statuses") if isinstance(status.get("policy_statuses"), list) else []
    policies, seen = [], set()
    for f in flags[:60]:
        if not isinstance(f, dict):
            continue
        pid = _s(_first(f, "id", "policy_id"), 20)
        r = runs.get(pid, {})
        seen.add(pid)
        policies.append({"id": pid, "name": _s(r.get("policy_name"), 120), "type": _s(r.get("policy_type_name"), 30),
                         "compliant": _bool(f.get("compliant")), "lastRun": _s(r.get("create_time"), 40),
                         "pendingCount": r.get("pending_count") if isinstance(r.get("pending_count"), int) else None,
                         "willReboot": _bool(r.get("will_reboot"))})
    for pid, r in list(runs.items())[:60]:
        if pid not in seen:
            policies.append({"id": pid, "name": _s(r.get("policy_name"), 120), "type": _s(r.get("policy_type_name"), 30),
                             "compliant": None, "lastRun": _s(r.get("create_time"), 40),
                             "pendingCount": r.get("pending_count") if isinstance(r.get("pending_count"), int) else None,
                             "willReboot": _bool(r.get("will_reboot"))})
    word = _s(status.get("policy_status"), 30).lower()
    if any(p["compliant"] is not None for p in policies):
        compliant = all(p["compliant"] is not False for p in policies)
    elif word in ("compliant", "non-compliant", "noncompliant"):
        compliant = word == "compliant"
    else:
        compliant = _bool(d.get("compliant"))
    tags = [_s(t, 60) for t in _list(d.get("tags"))[:30]]
    return {
        "id": _s(_first(d, "id", "server_id"), 30),
        "name": _s(_first(d, "name", "hostname"), 255),
        "display": _s(_first(d, "display_name", "custom_name"), 255),
        "os": _s(_first(d, "os_name"), 120), "osFamily": _s(d.get("os_family"), 40), "osVersion": _s(d.get("os_version"), 80),
        "serial": _s(_first(d, "serial_number") or detail.get("SERIAL"), 80),
        "ips": ips[:20],
        "agent": _s(d.get("agent_version"), 40),
        "lastSeen": _s(_first(d, "last_refresh_time", "last_seen", "last_check_in"), 40),
        "lastDisconnect": _s(d.get("last_disconnect_time"), 40),
        "connected": _bool(d.get("connected")),
        "needsReboot": _bool(_first(d, "needs_reboot", "needsReboot")),
        "pending": int(d.get("pending_patches") or 0) if str(d.get("pending_patches") or "0").isdigit() else 0,
        "upToDate": _bool(d.get("up_to_date")),
        "needsAttention": _bool(d.get("needs_attention")),
        "lastLoggedIn": _s(d.get("last_logged_in_user"), 80),
        "nextPatch": _s(d.get("next_patch_time"), 40),
        "compliant": compliant,
        "policies": policies,
        "deviceStatus": _s(status.get("device_status"), 30),
        "agentStatus": _s(status.get("agent_status"), 30),
        "group": _s(d.get("server_group_id"), 20),
        "tags": tags,
        "created": _s(d.get("create_time"), 40),
    }


def normalise_policy(p):
    """A policy's schedule and what it installs (v4.5.2). next_remediation is Automox's own next run; devices do not report one."""
    cfg = p.get("configuration") if isinstance(p.get("configuration"), dict) else {}
    sev = cfg.get("severity_filter")
    return {
        "id": _s(p.get("id"), 20), "name": _s(p.get("name"), 120), "type": _s(p.get("policy_type_name"), 30),
        "active": _s(p.get("status"), 20).lower() == "active", "auto": _bool(cfg.get("auto_patch")), "reboot": _bool(cfg.get("auto_reboot")),
        "rule": _s(cfg.get("patch_rule"), 20).lower(), "sev": [_s(x, 20).lower() for x in sev] if isinstance(sev, list) else None,
        "next": _s(p.get("next_remediation"), 40), "days": p.get("schedule_days") if isinstance(p.get("schedule_days"), int) else None,
        "weeks": p.get("schedule_weeks_of_month") if isinstance(p.get("schedule_weeks_of_month"), int) else None,
        "time": _s(p.get("schedule_time"), 10), "devices": p.get("server_count") if isinstance(p.get("server_count"), int) else None,
    }


def normalise_package(p, device_id=None):
    cves = [_s(c, 30).upper() for c in _list(p.get("cves"))[:80] if str(c).upper().startswith("CVE-")]
    kev = [_s(c, 30).upper() for c in _list(p.get("kev_cves"))[:40] if str(c).upper().startswith("CVE-")]
    def num(v):
        try:
            return round(float(v), 4) if v not in (None, "") else None
        except (TypeError, ValueError):
            return None
    return {
        "d": _s(device_id if device_id is not None else _first(p, "server_id", "device_id"), 30),
        "n": _s(_first(p, "display_name", "name"), 200), "v": _s(p.get("version"), 80),
        "sev": _s(_first(p, "severity", "agent_severity"), 20).lower(),
        "cves": cves, "kev": kev, "cveScore": num(p.get("cve_score")), "epss": num(p.get("epss_score")),
        "installed": _bool(p.get("installed")),
        "ignored": bool(_bool(p.get("ignored")) or _bool(p.get("group_ignored"))),
        "deferred": _s(_first(p, "deferred_until", "group_deferred_until"), 40),
        "reboot": _bool(p.get("requires_reboot")),
        "managed": _bool(p.get("is_managed")),
    }


# ------------------------------------------------------------------ the sync job

_job_lock = threading.Lock()
_job = {"running": False}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _meta(cur, kind):
    cur.execute("SELECT doc FROM automox WHERE kind='meta' AND k=%s", (kind,))
    r = cur.fetchone()
    return json.loads(r[0]) if r else None


def _put_meta(cur, kind, doc):
    cur.execute("REPLACE INTO automox (kind, k, doc) VALUES ('meta', %s, %s)", (kind, json.dumps(doc)))


def status():
    out = {"configured": configured(), "scheduleHours": HOURS, "job": dict(_job)}
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            out["last"] = _meta(cur, "last")
            out["error"] = _meta(cur, "err")
    except Exception as e:                              # table missing on a brand new database, etc.
        out["dbError"] = str(e)[:200]
    return out


def start(user, device_ids):
    """Start a sync in the background. False if one is running already."""
    if not configured():
        raise AxError("setup", "Automox is not set up on this server (no AUTOMOX_API_KEY). Run ./deploy.sh automox key")
    if not _job_lock.acquire(blocking=False):
        return False
    ids = sorted({_s(i, 30) for i in (device_ids or []) if str(i).strip()})
    _job.clear()
    _job.update({"running": True, "by": user, "started": now_iso(), "phase": "starting", "count": 0})
    threading.Thread(target=_run, args=(user, ids), name="automox-sync", daemon=True).start()
    return True


def _phase(name, count=0, total=None):
    _job.update({"phase": name, "count": count, "total": total})


def _run(user, ids):
    t0 = time.time()
    calls0 = _calls[0]
    try:
        result = sync(user, ids)
        result["seconds"] = round(time.time() - t0)
        result["calls"] = _calls[0] - calls0
        with _conn_ctx() as c, c.cursor() as cur:
            _put_meta(cur, "last", result)
            cur.execute("DELETE FROM automox WHERE kind='meta' AND k='err'")
            _audit(cur, user, "automox-sync", f"{result['devices']} devices, {result['pending']} pending patches, "
                                              f"{result['installedDevices']} devices checked for installed fixes")
    except Exception as e:
        kind = e.kind if isinstance(e, AxError) else "error"
        msg = str(e) if isinstance(e, AxError) else f"{type(e).__name__}: {str(e)[:300]}"
        try:
            with _conn_ctx() as c, c.cursor() as cur:
                _put_meta(cur, "err", {"at": now_iso(), "by": user, "kind": kind, "message": msg, "phase": _job.get("phase")})
                _audit(cur, user, "automox-sync-failed", msg)
        except Exception:
            pass
        _job.update({"error": msg, "errorKind": kind})
    finally:
        _job.update({"running": False, "finished": now_iso()})
        _job_lock.release()


def resolve_org():
    orgs = rows_of(get("/orgs"))
    found = [{"id": _s(o.get("id"), 20), "name": _s(o.get("name"), 120)} for o in orgs if isinstance(o, dict)]
    if ORG:
        hit = next((o for o in found if o["id"] == ORG), None)
        return ORG, (hit or {}).get("name", ""), found
    if len(found) == 1:
        return found[0]["id"], found[0]["name"], found
    if not found:
        raise AxError("org", "The API key can see no Automox organisation. Set AUTOMOX_ORG_ID in .env (./deploy.sh automox org ID).")
    raise AxError("org", "The API key can see several organisations; choose one with ./deploy.sh automox org ID: "
                         + ", ".join(f"{o['id']} ({o['name']})" for o in found[:20]))


def sync(user, ids):
    _phase("organisation")
    org, org_name, _ = resolve_org()

    _phase("devices")
    raw_devices = paged("/servers", {"o": org}, progress=lambda n: _phase("devices", n))
    devices = [normalise_device(d) for d in raw_devices]
    devices = [d for d in devices if d["id"]]
    device_fields = sorted(raw_devices[0].keys()) if raw_devices else []
    known = {d["id"] for d in devices}

    _phase("pending patches")
    raw_pending = paged(f"/orgs/{org}/packages", {"o": org, "awaiting": 1}, progress=lambda n: _phase("pending patches", n))
    package_fields = sorted(raw_pending[0].keys()) if raw_pending else []
    pending = [normalise_package(p) for p in raw_pending]
    pending = [p for p in pending if p["installed"] is not True]
    warnings = []
    if pending and not any(p["d"] for p in pending):
        warnings.append("Pending patches came back without a device id, so they cannot be linked to devices.")
    pending = [p for p in pending if p["d"]]

    # Patch policies: their schedules give each device's next patch run (read-only; a failure only loses the forecast).
    _phase("policies")
    policies = None
    try:
        policies = [normalise_policy(p) for p in paged("/policies", {"o": org}, progress=lambda n: _phase("policies", n))]
    except AxError as e:
        warnings.append(f"Patch policies could not be read ({e}), so the Patch Plan cannot tell when patches will be installed.")

    # Installed packages that carry CVEs, only for the devices the page asked about (assets with open tasks).
    want = [i for i in ids if i in known]
    if len(want) > MAX_DEVICE_CALLS:
        warnings.append(f"{len(want)} devices asked for; checked the first {MAX_DEVICE_CALLS} for installed fixes.")
        want = want[:MAX_DEVICE_CALLS]
    installed = []
    for n, dev in enumerate(want):
        _phase("installed fixes", n, len(want))
        try:
            rows = paged(f"/servers/{dev}/packages", {"o": org})
        except AxError as e:
            if e.kind in ("auth", "forbidden", "network", "rate"):
                raise
            warnings.append(f"device {dev}: {e}")
            continue
        for p in rows:
            q = normalise_package(p, dev)
            if q["installed"] is True and q["cves"]:
                installed.append(q)

    _phase("saving", 0)
    stamp = now_iso()
    with _conn_ctx() as c, c.cursor() as cur:
        # Automox gives no install date (create_time is when it catalogued the version: a 2023 kernel shows 2023).
        # So a fix counts as installed NOW only when we saw it waiting in the last sync and see it installed in this one.
        cur.execute("SELECT doc FROM automox WHERE kind='pend'")
        before = {}
        for (doc,) in cur.fetchall():
            p = json.loads(doc)
            for cve in p.get("cves") or []:
                before.setdefault((str(p.get("d")), cve), p.get("n", ""))
        still = {(p["d"], cve) for p in pending for cve in p["cves"]}
        now_in = {}
        for p in installed:
            for cve in p["cves"]:
                now_in.setdefault((p["d"], cve), f"{p['n']} {p['v']}".strip())
        checked = set(want)
        done = [(d, cve, now_in[(d, cve)]) for (d, cve) in before if d in checked and (d, cve) in now_in and (d, cve) not in still]
        for i in range(0, len(done), 1000):
            cur.executemany("INSERT IGNORE INTO automox (kind, k, doc) VALUES ('done', %s, %s)",
                            [(f"{d}|{cve}"[:80], json.dumps({"d": d, "cve": cve, "pkg": pkg, "at": stamp}, separators=(",", ":"))) for d, cve, pkg in done[i:i + 1000]])
        cur.execute("DELETE FROM automox WHERE kind='done' AND JSON_VALUE(doc, '$.at') < %s",
                    (datetime.fromtimestamp(time.time() - 180 * 86400, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),))
        cur.execute("DELETE FROM automox WHERE kind IN ('dev','pend','inst')")
        rows = [("dev", d["id"], json.dumps(d, separators=(",", ":"))) for d in devices]
        rows += [("pend", f"{i}", json.dumps(p, separators=(",", ":"))) for i, p in enumerate(pending)]
        rows += [("inst", f"{i}", json.dumps(p, separators=(",", ":"))) for i, p in enumerate(installed)]
        for i in range(0, len(rows), 1000):
            cur.executemany("INSERT INTO automox (kind, k, doc) VALUES (%s,%s,%s)", rows[i:i + 1000])
        _put_meta(cur, "req", {"ids": ids, "at": now_iso()})
        if policies is not None:
            _put_meta(cur, "pol", policies)
    return {"at": stamp, "by": user, "newlyInstalled": len(done), "org": org, "orgName": org_name, "devices": len(devices), "pending": len(pending),
            "installed": len(installed), "installedDevices": len(want), "checkedIds": want, "warnings": warnings,
            "policies": None if policies is None else len(policies),
            "deviceFields": device_fields[:80], "packageFields": package_fields[:80]}


def data_json():
    """Everything the page needs, as one JSON string."""
    parts = {"dev": [], "pend": [], "inst": [], "done": []}
    meta = None
    with _conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT kind, doc FROM automox WHERE kind IN ('dev','pend','inst','done')")
        for kind, doc in cur.fetchall():
            parts[kind].append(doc)
        meta = _meta(cur, "last")
        pol = _meta(cur, "pol") or []
    return ('{"meta":' + json.dumps(meta) + ',"policies":' + json.dumps(pol) + ',"devices":[' + ",".join(parts["dev"]) + '],"pending":[' + ",".join(parts["pend"])
            + '],"installed":[' + ",".join(parts["inst"]) + '],"done":[' + ",".join(parts["done"]) + "]}")


def _scheduler():
    """Sync every AUTOMOX_SYNC_HOURS, asking about the same devices as the last sync someone started."""
    time.sleep(120)
    while True:
        try:
            with _conn_ctx() as c, c.cursor() as cur:
                last, req, err = _meta(cur, "last"), _meta(cur, "req"), _meta(cur, "err")
            newest = max([x["at"] for x in (last, err) if x and x.get("at")] or ["1970-01-01T00:00:00Z"])
            age = time.time() - datetime.strptime(newest, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            if age >= HOURS * 3600:
                start("schedule", (req or {}).get("ids", []))
        except Exception:
            pass
        time.sleep(300)


# ------------------------------------------------------------------ command line check

def _cli_test():
    if not configured():
        print("AUTOMOX_API_KEY is not set")
        return 1
    try:
        org, name, found = resolve_org()
        print(f"organisations the key can see: {len(found)}")
        for o in found[:20]:
            print(f"  {o['id']}  {o['name']}")
        print(f"using organisation {org} {name}")
        page = rows_of(get("/servers", {"o": org, "limit": 50, "page": 0}))
        print(f"devices on the first page (up to 50): {len(page)}")
        if page:
            print("device fields:", ", ".join(sorted(page[0].keys())))
        pk = rows_of(get(f"/orgs/{org}/packages", {"o": org, "awaiting": 1, "limit": 50, "page": 0}))
        print(f"pending patches on the first page (up to 50): {len(pk)}")
        if pk:
            print("package fields:", ", ".join(sorted(pk[0].keys())))
            print("with a device id:", sum(1 for p in pk if normalise_package(p)["d"]), " with CVEs:", sum(1 for p in pk if normalise_package(p)["cves"]))
        return 0
    except AxError as e:
        print(f"FAILED ({e.kind}): {e}")
        return 2


if __name__ == "__main__":
    if sys.argv[1:] == ["test"]:
        sys.exit(_cli_test())
    print(__doc__)
