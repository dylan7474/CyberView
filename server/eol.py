"""End-of-life dates: endoflife.date API v1, fetched by the server on a schedule and kept in the database (v4.12).

The page reads them from /api/eol/data instead of every browser asking endoflife.date itself. endoflife.date is
public (no key). Every product the page knows how to match (EolDates.match in index.html) is fetched; a product
that cannot be fetched keeps its last saved copy.

    EOL_SYNC_HOURS   how often to fetch (default 24; 0 = only when someone presses Refresh dates)
    EOL_PRODUCTS     extra endoflife.date product names to fetch, comma separated (optional)

    python3 eol.py test      fetch one product and print what would be saved
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

BASE = os.environ.get("EOL_BASE_URL", "https://endoflife.date/api").rstrip("/")
try:
    HOURS = float(os.environ.get("EOL_SYNC_HOURS", "24") or 0)
except ValueError:
    HOURS = 24
# Keep in step with EolDates.match in index.html.
PRODUCTS = ["windows-server", "windows", "rhel", "almalinux", "rocky-linux", "oracle-linux", "centos", "debian",
            "ubuntu", "sles", "esxi", "vcenter", "cisco-ios-xe", "freebsd"]
PRODUCTS += [p.strip() for p in os.environ.get("EOL_PRODUCTS", "").split(",") if p.strip() and p.strip() not in PRODUCTS]
GAP = 1.0                     # seconds between requests: be polite to a free service

SCHEMA = """CREATE TABLE IF NOT EXISTS eol_dates (
    k VARCHAR(80) NOT NULL PRIMARY KEY,
    doc LONGTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""

_conn_ctx = None
_audit = None
_job_lock = threading.Lock()
_job = {"running": False}


def init(conn_ctx, audit):
    global _conn_ctx, _audit
    _conn_ctx, _audit = conn_ctx, audit
    if HOURS > 0:
        threading.Thread(target=_scheduler, name="eol-schedule", daemon=True).start()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "CyberView (end-of-life dates)"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def _when(date, flag):
    return date if date else bool(flag)


def from_v1(r):
    """One v1 release -> the shape the page reads: cycle, eol, support, extEnd, latest (dates, True = ended, False = no date)."""
    out = {"cycle": str(r.get("name")), "eol": _when(r.get("eolFrom"), r.get("isEol"))}
    if "isEoas" in r:
        out["support"] = _when(r.get("eoasFrom"), r.get("isEoas"))
    if "isEoes" in r:
        out["extEnd"] = _when(r.get("eoesFrom"), r.get("isEoes"))
    latest = r.get("latest") or {}
    if isinstance(latest, dict) and latest.get("name"):
        out["latest"] = str(latest["name"])
    if r.get("releaseDate"):
        out["releaseDate"] = r["releaseDate"]
    return out


def fetch_product(p):
    """API v1 first; the older /api/<p>.json if v1 fails. Returns a list or raises."""
    q = urllib.parse.quote(p)
    for attempt in (1, 2):                   # one retry: a busy moment should not drop us to the older API
        try:
            j = _get_json(f"{BASE}/v1/products/{q}")
            rel = (j.get("result") or {}).get("releases")
            if isinstance(rel, list) and rel:
                return [from_v1(r) for r in rel], "v1"
        except Exception as e:
            _job["lastV1Error"] = f"{p}: {type(e).__name__}: {str(e)[:120]}"
        if attempt == 1:
            time.sleep(3)
    old = _get_json(f"{BASE}/{q}.json")
    if isinstance(old, list) and old:
        return old, "v0"
    raise ValueError("no releases")


def _put(cur, k, doc):
    cur.execute("REPLACE INTO eol_dates (k, doc) VALUES (%s, %s)", (k, json.dumps(doc, separators=(",", ":"))))


def _get(cur, k):
    cur.execute("SELECT doc FROM eol_dates WHERE k=%s", (k,))
    r = cur.fetchone()
    return json.loads(r[0]) if r else None


def status():
    out = {"scheduleHours": HOURS, "products": PRODUCTS, "job": dict(_job)}
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            out["last"] = _get(cur, "meta:last")
    except Exception as e:
        out["last"] = None
        out["dbError"] = str(e)[:200]
    return out


def start(user):
    with _job_lock:
        if _job.get("running"):
            return False
        _job.clear()
        _job.update({"running": True, "by": user, "startedAt": now_iso(), "done": 0, "total": len(PRODUCTS)})
    threading.Thread(target=_run, args=(user,), name="eol-sync", daemon=True).start()
    return True


def _run(user):
    ok, failed, old = [], [], []
    try:
        for i, p in enumerate(PRODUCTS):
            try:
                rows, how = fetch_product(p)
                with _conn_ctx() as c, c.cursor() as cur:
                    _put(cur, "p:" + p, {"at": now_iso(), "list": rows})
                ok.append(p)
                if how != "v1":
                    old.append(p)
            except Exception:
                failed.append(p)               # keep the last saved copy
            _job["done"] = i + 1
            time.sleep(GAP)
        meta = {"at": now_iso(), "by": user, "ok": ok, "failed": failed, "olderApi": old}
        if _job.get("lastV1Error"):
            meta["lastV1Error"] = _job["lastV1Error"]
        with _conn_ctx() as c, c.cursor() as cur:
            _put(cur, "meta:last", meta)
        if _audit and user != "schedule":
            try:
                _audit(user, "eol.sync", f"{len(ok)} products, {len(failed)} failed")
            except Exception:
                pass
    finally:
        _job["running"] = False
        _job["finishedAt"] = now_iso()


def data_json():
    """{meta, products: {product: {at, list}}} as one JSON string."""
    parts, meta = [], None
    with _conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT k, doc FROM eol_dates")
        for k, doc in cur.fetchall():
            if k.startswith("p:"):
                parts.append(json.dumps(k[2:]) + ":" + doc)
            elif k == "meta:last":
                meta = doc
    return '{"meta":' + (meta or "null") + ',"products":{' + ",".join(parts) + "}}"


def _scheduler():
    """Fetch every EOL_SYNC_HOURS (the first time about a minute after start-up if nothing is saved yet)."""
    time.sleep(60)
    while True:
        try:
            with _conn_ctx() as c, c.cursor() as cur:
                last = _get(cur, "meta:last")
            age = 1e12 if not last else time.time() - datetime.strptime(last["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            if age >= HOURS * 3600:
                start("schedule")
        except Exception:
            pass
        time.sleep(600)


if __name__ == "__main__" and sys.argv[1:] == ["test"]:
    rows, how = fetch_product("rhel")
    print(f"rhel via {how}: {len(rows)} releases; first: {json.dumps(rows[0])}")
