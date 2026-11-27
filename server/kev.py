"""The CISA Known Exploited Vulnerabilities list on the server (v4.44, database stage 3).

The browser has always fetched this list itself; the server now keeps a copy too, so its own rules (rules.py) know
which findings are known exploited. Public data, no key. Kept in the database (table kev_cve), refreshed every
KEV_SYNC_HOURS (default 24; 0 = only when asked). The same file the browser uses (a mirror of CISA's catalogue).

    KEV_SYNC_HOURS   how often to refresh (default 24; 0 = only on request)
"""
import json
import os
import threading
import time
import urllib.request
from datetime import datetime, timezone

URL = "https://cdn.jsdelivr.net/gh/cisagov/kev-data@develop/known_exploited_vulnerabilities.json"
try:
    HOURS = float(os.environ.get("KEV_SYNC_HOURS", "24") or 0)
except ValueError:
    HOURS = 24

SCHEMA = """CREATE TABLE IF NOT EXISTS kev_cve (
    cve VARCHAR(40) NOT NULL PRIMARY KEY,
    doc LONGTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""

_conn_ctx = None
_audit = None
_job = {"running": False}
_lock = threading.Lock()


def init(conn_ctx, audit):
    global _conn_ctx, _audit
    _conn_ctx, _audit = conn_ctx, audit
    if HOURS > 0:
        threading.Thread(target=_scheduler, name="kev-schedule", daemon=True).start()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def store(cur, catalogue, by="schedule"):
    """Replace the list with a catalogue in CISA's format ({vulnerabilities: [...]}). Returns how many CVEs."""
    vulns = [v for v in (catalogue or {}).get("vulnerabilities") or [] if isinstance(v, dict) and str(v.get("cveID", "")).upper().startswith("CVE-")]
    cur.execute("DELETE FROM kev_cve")
    rows = [(str(v["cveID"]).upper(), json.dumps({"added": v.get("dateAdded"), "due": v.get("dueDate"), "action": v.get("requiredAction"),
                                                  "name": v.get("vulnerabilityName"), "ransomware": v.get("knownRansomwareCampaignUse")}, separators=(",", ":"))) for v in vulns]
    for i in range(0, len(rows), 1000):
        cur.executemany("REPLACE INTO kev_cve (cve, doc) VALUES (%s,%s)", rows[i:i + 1000])
    cur.execute("REPLACE INTO kev_cve (cve, doc) VALUES ('meta:last', %s)", (json.dumps({"at": now_iso(), "by": by, "count": len(rows), "version": (catalogue or {}).get("catalogVersion")}),))
    return len(rows)


def cves(cur):
    cur.execute("SELECT cve FROM kev_cve WHERE cve LIKE 'CVE-%%'")
    return {r[0] for r in cur.fetchall()}


def status():
    out = {"scheduleHours": HOURS, "job": dict(_job)}
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            cur.execute("SELECT doc FROM kev_cve WHERE cve='meta:last'")
            r = cur.fetchone()
            out["last"] = json.loads(r[0]) if r else None
    except Exception as e:      # noqa: BLE001
        out["dbError"] = str(e)[:200]
    return out


def start(user):
    with _lock:
        if _job.get("running"):
            return False
        _job.clear()
        _job.update({"running": True, "by": user, "startedAt": now_iso()})
    threading.Thread(target=_run, args=(user,), name="kev-sync", daemon=True).start()
    return True


def _run(user):
    try:
        req = urllib.request.Request(URL, headers={"Accept": "application/json", "User-Agent": "CyberView (CISA KEV list)"})
        with urllib.request.urlopen(req, timeout=60) as r:
            cat = json.loads(r.read().decode("utf-8"))
        with _conn_ctx() as c, c.cursor() as cur:
            n = store(cur, cat, user)
        _job["count"] = n
    except Exception as e:      # noqa: BLE001
        _job["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    finally:
        _job["running"] = False
        _job["finishedAt"] = now_iso()


def _scheduler():
    time.sleep(45)
    while True:
        try:
            last = (status().get("last") or {}).get("at")
            age = (time.time() - datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()) / 3600 if last else 1e9
            if age >= HOURS:
                start("schedule")
        except Exception:      # noqa: BLE001
            pass
        time.sleep(3600)
