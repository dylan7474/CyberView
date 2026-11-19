"""Red Hat Security Data API (public, no key): what Red Hat says about a CVE, per RHEL release (v4.22).

    https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json

Only CVE numbers are sent. Each answer is kept in the database for a day (table redhat_cve), so the page asks the server
and the server asks Red Hat at most once a day per CVE. The watched CVEs (gov_cve_watch) are refreshed by a daily job.

    REDHAT_SYNC_HOURS   how often the watched CVEs are refreshed (default 24; 0 = only when someone looks)

    python3 redhat.py test      fetch one CVE and print what would be saved
"""
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

BASE = os.environ.get("REDHAT_BASE_URL", "https://access.redhat.com/hydra/rest/securitydata").rstrip("/")
try:
    HOURS = float(os.environ.get("REDHAT_SYNC_HOURS", "24") or 0)
except ValueError:
    HOURS = 24
KEEP_HOURS = 24                 # an answer is reused for a day
GAP = 0.5                       # seconds between requests to Red Hat
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

SCHEMA = """CREATE TABLE IF NOT EXISTS redhat_cve (
    k VARCHAR(40) NOT NULL PRIMARY KEY,
    at DATETIME NOT NULL,
    doc LONGTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""

_conn_ctx = None
_lock = threading.Lock()


def init(conn_ctx, audit=None):
    global _conn_ctx
    _conn_ctx = conn_ctx
    if HOURS > 0:
        threading.Thread(target=_scheduler, name="redhat-schedule", daemon=True).start()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _txt(v, n):
    if isinstance(v, dict):
        v = v.get("value") or ""
    return re.sub(r"\s+", " ", str(v or "")).strip()[:n]


def normalise(cve, j):
    """The parts the page uses: severity, scores, statement, mitigation, fixed releases and per-release states."""
    cvss = j.get("cvss3") or {}
    fixed = [{"p": r.get("product_name") or "", "a": r.get("advisory") or "", "pkg": r.get("package") or "", "d": (r.get("release_date") or "")[:10]}
             for r in (j.get("affected_release") or [])]
    states = [{"p": r.get("product_name") or "", "s": r.get("fix_state") or "", "pkg": r.get("package_name") or ""}
              for r in (j.get("package_state") or [])]
    return {"cve": cve, "at": now_iso(), "severity": j.get("threat_severity") or "", "cvss": cvss.get("cvss3_base_score") or "",
            "public": (j.get("public_date") or "")[:10], "statement": _txt(j.get("statement"), 900), "mitigation": _txt(j.get("mitigation"), 900),
            "fixed": fixed[:200], "states": states[:200]}


def fetch(cve):
    """One CVE from Red Hat. {"none": True} when Red Hat has no page for it (404)."""
    req = urllib.request.Request(f"{BASE}/cve/{cve}.json", headers={"Accept": "application/json", "User-Agent": "CyberView (security data)"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return normalise(cve, json.loads(r.read().decode("utf-8")))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"cve": cve, "at": now_iso(), "none": True}
        raise


def _cached(cur, cve):
    cur.execute("SELECT doc, at FROM redhat_cve WHERE k=%s", (cve,))
    r = cur.fetchone()
    if not r:
        return None, None
    return json.loads(r[0]), r[1]


def get(cves, force=False):
    """{cve: doc} for up to 20 CVEs: from the database when under a day old, else from Red Hat (a failure keeps the old copy)."""
    want = sorted({str(c).strip().upper() for c in (cves or []) if CVE_RE.match(str(c).strip().upper())})[:20]
    out, now = {}, datetime.now(timezone.utc).replace(tzinfo=None)
    for cve in want:
        doc, at = None, None
        try:
            with _conn_ctx() as c, c.cursor() as cur:
                doc, at = _cached(cur, cve)
        except Exception:
            doc = None
        fresh = doc is not None and at is not None and (now - at).total_seconds() < KEEP_HOURS * 3600
        if fresh and not force:
            out[cve] = doc
            continue
        try:
            with _lock:
                new = fetch(cve)
                time.sleep(GAP)
            with _conn_ctx() as c, c.cursor() as cur:
                cur.execute("REPLACE INTO redhat_cve (k, at, doc) VALUES (%s, UTC_TIMESTAMP(), %s)", (cve, json.dumps(new, separators=(",", ":"))))
            out[cve] = new
        except Exception as e:
            if doc is not None:
                out[cve] = {**doc, "stale": True}
            else:
                out[cve] = {"cve": cve, "error": f"{type(e).__name__}: {str(e)[:120]}"}
    return out


def _watched():
    """The open pins of the Watched CVEs record (one JSON object: {"pins": [...]})."""
    with _conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT doc FROM records WHERE collection='gov_cve_watch' ORDER BY seq LIMIT 1")
        r = cur.fetchone()
    try:
        d = json.loads(r[0]) if r else {}
    except ValueError:
        d = {}
    return [p["cve"] for p in (d.get("pins") or []) if isinstance(p, dict) and p.get("cve") and not p.get("closedAt")]


_job = {"running": False}


def refresh_watched(user="schedule"):
    """Fetch every watched CVE again now and record the run (Data Health shows it)."""
    cves, ok, failed = _watched(), [], []
    for i in range(0, len(cves), 20):
        for cve, d in get(cves[i:i + 20], force=True).items():
            (failed if d.get("error") or d.get("stale") else ok).append(cve)
    meta = {"at": now_iso(), "by": user, "ok": len(ok), "failed": failed[:50]}
    with _conn_ctx() as c, c.cursor() as cur:
        cur.execute("REPLACE INTO redhat_cve (k, at, doc) VALUES ('meta:last', UTC_TIMESTAMP(), %s)", (json.dumps(meta),))
    return meta


def start(user):
    """Data Health's Sync now. False if a refresh is already running."""
    if _job.get("running"):
        return False
    _job.update({"running": True, "by": user, "startedAt": now_iso()})

    def run():
        try:
            refresh_watched(user)
        except Exception as e:
            _job["error"] = f"{type(e).__name__}: {str(e)[:150]}"
        finally:
            _job["running"] = False
    threading.Thread(target=run, name="redhat-sync", daemon=True).start()
    return True


def status():
    out = {"scheduleHours": HOURS, "keepHours": KEEP_HOURS, "job": dict(_job)}
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            cur.execute("SELECT doc FROM redhat_cve WHERE k='meta:last'")
            r = cur.fetchone()
            out["last"] = json.loads(r[0]) if r else None
            cur.execute("SELECT COUNT(*), MAX(at) FROM redhat_cve WHERE k LIKE 'CVE-%%'")
            n, newest = cur.fetchone()
            out["cves"] = int(n or 0)
            out["newest"] = newest.strftime("%Y-%m-%dT%H:%M:%SZ") if newest else None
        out["watched"] = len(_watched())
    except Exception as e:
        out["dbError"] = str(e)[:200]
    return out


def _scheduler():
    """Refresh the watched CVEs every REDHAT_SYNC_HOURS (first about two minutes after start-up)."""
    time.sleep(120)
    while True:
        if not _job.get("running"):
            _job["running"] = True
            try:
                refresh_watched("schedule")
            except Exception:
                pass
            finally:
                _job["running"] = False
        time.sleep(max(1.0, HOURS) * 3600)


if __name__ == "__main__" and sys.argv[1:] == ["test"]:
    d = fetch("CVE-2024-6387")
    print(json.dumps({k: d[k] for k in ("severity", "cvss", "public")}), len(d["fixed"]), "fixed,", len(d["states"]), "states")
    print([(s["p"], s["s"]) for s in d["states"] if "Enterprise Linux" in s["p"]])
