"""EPSS (Exploit Prediction Scoring System) from FIRST (api.first.org), fetched by the server (v4.35).

EPSS is a public, daily 0-1 score per CVE estimating how likely that vulnerability is to be exploited in the
wild within the next 30 days, plus its percentile against every published CVE (https://www.first.org/epss/).
The portal keeps a copy of every CVE its own QID catalogue knows about, refreshed on a schedule, so a team can
rank and raise findings where exploitation is likely (a threshold on the Status rules page) without every
browser asking FIRST. Only CVE numbers are sent; no machine names, hosts or addresses.

The CVE list comes from the portal's own `qids` table, so it works whether the findings came from the Qualys
API sync or a CSV import. A CVE FIRST does not know is simply not stored; a product that cannot be fetched
keeps its last saved copy (status shows both).

    EPSS_SYNC_HOURS   how often the whole catalogue is refreshed (default 24; 0 = only when someone presses
                      Sync now on Data Health)

    python3 epss.py test      fetch one CVE and print what would be saved
"""
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BASE = os.environ.get("EPSS_BASE_URL", "https://api.first.org/data/v1/epss").rstrip("/")
try:
    HOURS = float(os.environ.get("EPSS_SYNC_HOURS", "24") or 0)
except ValueError:
    HOURS = 24
BATCH = 100                       # CVEs per request: keep each URL and reply small
GAP = 0.5                         # seconds between requests: be polite to a free service
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

SCHEMA = """CREATE TABLE IF NOT EXISTS epss_cve (
    k VARCHAR(40) NOT NULL PRIMARY KEY,
    at DATETIME NOT NULL,
    doc LONGTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""

_conn_ctx = None
_audit = None
_job_lock = threading.Lock()
_job = {"running": False}


def init(conn_ctx, audit):
    """Called by app.py at startup with its database helpers."""
    global _conn_ctx, _audit
    _conn_ctx, _audit = conn_ctx, audit
    if HOURS > 0:
        threading.Thread(target=_scheduler, name="epss-schedule", daemon=True).start()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cve_of(c):
    """A CVE id from either shape the QID catalogue stores: a plain id or {'id', ...}."""
    return (c if isinstance(c, str) else (c or {}).get("id")) or ""


def _all_cves(cur):
    """Every CVE the portal's QID catalogue knows. Empty when there is no vulnerability data yet."""
    out = set()
    cur.execute("SELECT doc FROM qids")
    for (doc,) in cur.fetchall():
        try:
            q = json.loads(doc)
        except ValueError:
            continue
        for c in q.get("cves") or []:
            id_ = _cve_of(c).strip()
            if CVE_RE.match(id_):
                out.add(id_)
    return out


def _get_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "CyberView (EPSS scores)"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def fetch_chunk(cves):
    """One request to FIRST for up to BATCH CVEs: {cve_id: {epss, pct}}. Raises on network/HTTP errors."""
    q = "?cve=" + ",".join(urllib.parse.quote(c, safe="") for c in cves)
    j = _get_json(BASE + q)
    out = {}
    for d in (j or {}).get("data") or []:
        cve = str(d.get("cve", ""))
        if not CVE_RE.match(cve):
            continue
        try:
            out[cve] = {"epss": float(d["epss"]), "pct": float(d.get("percentile") or 0)}
        except (KeyError, TypeError, ValueError):
            pass
    return out


def _put(cur, k, doc):
    cur.execute("REPLACE INTO epss_cve (k, at, doc) VALUES (%s, UTC_TIMESTAMP(), %s)", (k, json.dumps(doc, separators=(",", ":"))))


def _get(cur, k):
    cur.execute("SELECT doc FROM epss_cve WHERE k=%s", (k,))
    r = cur.fetchone()
    return json.loads(r[0]) if r else None


def status():
    out = {"scheduleHours": HOURS, "batch": BATCH, "job": dict(_job)}
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            out["last"] = _get(cur, "meta:last")
            cur.execute("SELECT COUNT(*), MAX(at) FROM epss_cve WHERE k LIKE 'CVE-%%'")
            n, newest = cur.fetchone()
            out["cves"] = int(n or 0)
            out["newest"] = newest.strftime("%Y-%m-%dT%H:%M:%SZ") if newest else None
    except Exception as e:                              # table missing on a brand new database, etc.
        out["dbError"] = str(e)[:200]
    return out


def start(user):
    """Refresh the scores for every CVE the portal holds, in the background. False if one is running already."""
    with _job_lock:
        if _job.get("running"):
            return False
        _job.clear()
        _job.update({"running": True, "by": user, "startedAt": now_iso()})
    threading.Thread(target=_run, args=(user,), name="epss-sync", daemon=True).start()
    return True


def _run(user):
    ok, failed = 0, []
    t0 = time.time()
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            cves = sorted(_all_cves(cur))
        chunks = [cves[i:i + BATCH] for i in range(0, len(cves), BATCH)] or [[]]
        for chunk in chunks:
            try:
                fresh = fetch_chunk(chunk)
                with _conn_ctx() as c, c.cursor() as cur:
                    for cve, val in fresh.items():
                        _put(cur, cve, val)
                ok += len(fresh)
            except Exception as e:
                label = chunk[0] if chunk else "no CVEs"
                failed.append(f"{label}…: {type(e).__name__}: {str(e)[:120]}")
            _job["count"] = ok
            time.sleep(GAP)
        with _conn_ctx() as c, c.cursor() as cur:
            _put(cur, "meta:last", {"at": now_iso(), "by": user, "ok": ok, "cves": len(cves),
                                    "seconds": round(time.time() - t0), "failed": failed[:20]})
        if _audit and user != "schedule":
            try:
                _audit(user, "epss.sync", f"{ok} CVE scores, {len(failed)} failed")
            except Exception:
                pass
    except Exception as e:
        _job["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    finally:
        _job["running"] = False
        _job["finishedAt"] = now_iso()


def data_json():
    """{meta, cves: {cve: {epss, pct}}} as one JSON string."""
    parts, meta = [], None
    with _conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT k, doc FROM epss_cve")
        for k, doc in cur.fetchall():
            if k.startswith("CVE-"):
                parts.append(json.dumps(k) + ":" + doc)
            elif k == "meta:last":
                meta = doc
    return '{"meta":' + (meta or "null") + ',"cves":{' + ",".join(parts) + "}}"


def _scheduler():
    """Refresh when the last run is older than EPSS_SYNC_HOURS and there is a QID catalogue to score."""
    time.sleep(60)
    while True:
        try:
            with _conn_ctx() as c, c.cursor() as cur:
                last = _get(cur, "meta:last")
                cur.execute("SELECT COUNT(*) FROM qids")
                nq = cur.fetchone()[0]
            age = 1e12 if not last else time.time() - datetime.strptime(last["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            if nq and age >= HOURS * 3600:
                start("schedule")
        except Exception:
            pass
        time.sleep(300)


if __name__ == "__main__" and sys.argv[1:] == ["test"]:
    print("EPSS for CVE-2024-6387:", json.dumps(fetch_chunk(["CVE-2024-6387"])))