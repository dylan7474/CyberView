"""Qualys: read-only sync of vulnerability detections, the KnowledgeBase and asset scores into the portal's database.

Replaces the capped CSV export (50,000 rows, 500 per asset) with the full data set from the Qualys APIs:
  * VM Host List API          hosts in scope with their last scan date      /api/2.0/fo/asset/host/
  * Host List Detection API   every finding (New, Active, Re-Opened, Fixed)  /api/2.0/fo/asset/host/vm/detection/
  * KnowledgeBase API         QID -> title, CVEs, threat flags, solution, CVSS (when the subscription has CVSS Scoring on)    /api/2.0/fo/knowledge_base/vuln/
  * CSAM asset search         TruRisk score, asset criticality, tags        (gateway) /rest/2.0/search/am/asset
Every call only reads. The login (QUALYS_USERNAME + QUALYS_PASSWORD_B64) stays on the server; the page only sees
`configured: true/false`. A login that Qualys refuses blocks further syncs until the password is changed
(./deploy.sh qualys pass) or unblocked, so a wrong password can never lock the account by repeated attempts.

The finished sync is stored as one package (meta 'last' + chunk rows) that the page fetches from /api/qualys/data
and applies the same way as a CSV import. A sync is published only when every step succeeded.

    python3 qualys.py test       check the login and reach, one small page of each API (prints no secrets)
    python3 qualys.py watch      follow the running (or next) sync step by step until it finishes
    python3 qualys.py unblock    allow syncs again after a refused login (when the password was right after all)
"""
import base64
import hashlib
import html
import http.client
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def _b64(name):
    v = os.environ.get(name, "").strip()
    try:
        return base64.b64decode(v).decode("utf-8") if v else ""
    except Exception:
        return ""


API = os.environ.get("QUALYS_API_URL", "").strip().rstrip("/")
GATEWAY = (os.environ.get("QUALYS_GATEWAY_URL", "").strip().rstrip("/")
           or (API.replace("://qualysapi.", "://gateway.", 1) if API else ""))
USER = os.environ.get("QUALYS_USERNAME", "").strip()
PASSWORD = _b64("QUALYS_PASSWORD_B64")
TAG = _b64("QUALYS_SCOPE_TAG_B64")                        # empty = every host the account can see
try:
    HOUR = int(os.environ.get("QUALYS_SYNC_HOUR", "").strip() or -1)   # UTC hour for the daily sync; -1 = off
except ValueError:
    HOUR = -1
HOSTS_PER_PAGE = int(os.environ.get("QUALYS_HOSTS_PER_PAGE", "100") or 100)
KB_BATCH = 200                     # QIDs per KnowledgeBase call (1000 makes replies Qualys cuts off part-way)
CSAM_PAGE = 300
CHUNK_HOSTS = 40                   # hosts per stored package row (keeps rows well under max_allowed_packet)
MAX_CALLS = 280                    # Qualys allows 300 calls an hour per user; stop before that
CLAIM_MINUTES = 30
HISTORY_KEEP = 30                  # syncs kept in the history (successes and failures)
STEPS = [("hosts", "Hosts"), ("findings", "Findings"), ("kb", "KnowledgeBase"), ("scores", "Asset scores"), ("save", "Saving")]

SCHEMA = """CREATE TABLE IF NOT EXISTS qualys (
    kind VARCHAR(10) NOT NULL,
    k VARCHAR(80) NOT NULL,
    doc LONGTEXT NOT NULL,
    PRIMARY KEY (kind, k)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""

# KnowledgeBase threat-intelligence names -> the wording the CSV export (and so PriorityEngine) uses.
RTI = {
    "Active_Attacks": "Active Attacks", "Cisa_Known_Exploited_Vulns": "CISA Known Exploited Vulnerabilities",
    "Denial_of_Service": "Denial Of Service", "Easy_Exploit": "Easy Exploit", "Exploit_Kit": "Exploit Kit",
    "Exploit_Public": "Public Exploit", "High_Data_Loss": "High Data Loss", "High_Lateral_Movement": "High Lateral Movement",
    "Malware": "Malware Name", "No_Patch": "Patch Not Available", "Predicted_High_Risk": "Predicted High Risk",
    "Privilege_Escalation": "Privilege Escalation", "Ransomware": "Ransomware", "Remote_Code_Execution": "Remote Code Execution",
    "Unauthenticated_Exploitation": "Unauthenticated Exploitation", "Wormable": "Wormable", "Zero_Day": "Zero Day",
}
STATUS = {"active": "ACTIVE", "new": "NEW", "re-opened": "REOPENED", "reopened": "REOPENED", "fixed": "FIXED"}

_conn_ctx = None
_audit = None


def init(conn_ctx, audit):
    """Called by app.py at startup with its database helpers."""
    global _conn_ctx, _audit
    _conn_ctx, _audit = conn_ctx, audit
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            j = _meta(cur, "job")
            if j and j.get("running"):          # the app stopped mid-sync (restart, deploy): say so, do not show it running forever
                j.update(running=False, finished=now_iso(), error="Interrupted: the portal restarted during the sync", errorKind="interrupted")
                for st in j.get("steps") or []:
                    if st.get("state") == "running":
                        st["state"] = "failed"
                _put_meta(cur, "job", j)
                _put_meta(cur, "err", {"at": now_iso(), "by": j.get("by"), "kind": "interrupted", "message": j["error"], "phase": j.get("phase")})
                _put_history(cur, _history_doc(j, ok=False))
    except Exception:
        pass
    if configured() and 0 <= HOUR <= 23:
        threading.Thread(target=_scheduler, name="qualys-schedule", daemon=True).start()


def configured():
    return bool(API and USER and PASSWORD)


def fingerprint():
    """Identifies the current login without revealing it (to know whether a refused login has been changed)."""
    return hashlib.sha256(f"{API}\0{USER}\0{PASSWORD}".encode()).hexdigest()[:16]


class QxError(Exception):
    """kind: setup | blocked | auth | network | rate | http | data. The message never contains the password."""
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


# ------------------------------------------------------------------ HTTP

_calls = [0]
_RETRYABLE = (urllib.error.URLError, http.client.IncompleteRead, http.client.RemoteDisconnected,
              ConnectionError, TimeoutError, ssl.SSLError)


def _auth_failed(where, code):
    msg = (f"Qualys refused the login ({code} from {where}). Syncs are stopped so the account is not locked by "
           f"repeated attempts. Check the user name and password, then run ./deploy.sh qualys pass "
           f"(or ./deploy.sh qualys unblock if the password was right).")
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            _put_meta(cur, "authfail", {"fp": fingerprint(), "at": now_iso(), "where": where, "code": code})
    except Exception:
        pass
    return QxError("auth", msg)


def _request(url, data, headers, where, login=True):
    """One HTTP call with retries for dropped connections (seen ~1 in 20 on the Qualys API), rate limits and 5xx.
    A refused login (401) is never retried."""
    last = None
    for attempt in range(6):
        if _calls[0] >= MAX_CALLS:
            raise QxError("rate", f"Stopped after {MAX_CALLS} calls to stay inside Qualys's hourly limit")
        _calls[0] += 1
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                _rate(r.headers if url.startswith(API) else {})    # the gateway has its own, different allowance
                return r.status, r.read(), r.headers
        except urllib.error.HTTPError as e:
            body = e.read()
            if e.code == 401 and login:                  # the user name / password were refused
                raise _auth_failed(where, 401)
            if e.code == 401:                            # a gateway token expired: the caller gets a new one
                return e.code, body, e.headers
            if e.code in (409, 429) and attempt < 5:      # concurrency or rate limit: Qualys says how long to wait
                try:
                    wait = int(e.headers.get("X-RateLimit-ToWait-Sec") or 0)
                except ValueError:
                    wait = 0
                if wait > 900:
                    raise QxError("rate", f"Qualys asks us to wait {wait // 60} minutes (API limit reached); try later")
                _log("wait", f"{where}: Qualys is busy ({e.code}), waiting {max(wait, 20)} s")
                time.sleep(max(wait, 20))
                continue
            if e.code >= 500 and attempt < 5:
                _log("retry", f"{where}: Qualys answered {e.code}, trying again ({attempt + 1} of 5)")
                time.sleep(5 * (attempt + 1))
                continue
            return e.code, body, e.headers
        except _RETRYABLE as e:
            last = e
            _log("retry", f"{where}: connection dropped ({getattr(e, 'reason', None) or type(e).__name__}), trying again ({attempt + 1} of 5)")
            time.sleep(2 * (attempt + 1))
    host = urllib.parse.urlsplit(url).hostname
    raise QxError("network", f"Could not reach {host}: {getattr(last, 'reason', None) or type(last).__name__}. "
                             "Check the server can make HTTPS connections out to it (DNS, firewall, proxy).")


def vm(path, params, what):
    """POST to the VM API (form-encoded, so long QID lists fit) and return the parsed XML root."""
    tok = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    code, body, _ = _request(API + path, urllib.parse.urlencode(params).encode(),
                             {"Authorization": "Basic " + tok, "X-Requested-With": "governance-portal",
                              "Content-Type": "application/x-www-form-urlencoded"}, what)
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        raise QxError("data", f"Qualys sent something that is not XML for {what} (HTTP {code})")
    if root.tag == "SIMPLE_RETURN" or code != 200:
        text = root.findtext(".//TEXT") or ""
        num = root.findtext(".//CODE") or str(code)
        if num in ("2000", "2002", "2003") or "password" in text.lower() and "invalid" in text.lower():
            raise _auth_failed(what, num)
        raise QxError("http", f"Qualys answered {code} for {what}: {num} {text[:200]}")
    return root


_jwt = {"token": "", "at": 0.0}


def gateway(path, payload, what):
    """POST JSON to the gateway (CSAM) with a short-lived token made from the same login (renewed once if refused)."""
    for attempt in range(2):
        if attempt or not _jwt["token"] or time.time() - _jwt["at"] > 3 * 3600:
            code, body, _ = _request(GATEWAY + "/auth", urllib.parse.urlencode(
                {"username": USER, "password": PASSWORD, "token": "true"}).encode(),
                {"Content-Type": "application/x-www-form-urlencoded"}, "gateway login")
            if code not in (200, 201):
                raise QxError("http", f"The gateway login answered {code}")
            _jwt.update(token=body.decode().strip(), at=time.time())
        code, body, _ = _request(GATEWAY + path, json.dumps(payload).encode(),
                                 {"Authorization": "Bearer " + _jwt["token"], "Content-Type": "application/json",
                                  "Accept": "application/json"}, what, login=False)
        if code != 401:
            break
    if code != 200:
        raise QxError("http", f"Qualys gateway answered {code} for {what}")
    try:
        return json.loads(body)
    except ValueError:
        raise QxError("data", f"The gateway sent something that is not JSON for {what}")


def _scope(params):
    if TAG:
        params.update({"use_tags": 1, "tag_set_by": "name", "tag_set_include": TAG})
    return params


def _next_id(root):
    """Qualys pages by host id: the WARNING element carries the URL of the next page."""
    w = root.find(".//WARNING")
    if w is None:
        return None
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(w.findtext("URL") or "").query)
    return (q.get("id_min") or [None])[0]


# ------------------------------------------------------------------ normalising

def _txt(v, n):
    """KnowledgeBase text is HTML: plain text, single spaces, cut to n characters."""
    v = html.unescape(re.sub(r"<[^>]+>", " ", v or ""))
    return re.sub(r"\s+", " ", v).strip()[:n]


def _int(v, default=0):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _num(v):
    try:
        return round(float(str(v).strip().split()[0]), 1)
    except (TypeError, ValueError, IndexError):
        return 0


def normalise_kb(v):
    cves = [c.findtext("ID") for c in v.findall("./CVE_LIST/CVE") if (c.findtext("ID") or "").startswith("CVE-")]
    rti = []
    for t in v.findall("./THREAT_INTELLIGENCE/THREAT_INTEL"):
        name = (t.text or "").strip()
        if name:
            rti.append(RTI.get(name, name.replace("_", " ")))
    return {
        "qid": v.findtext("QID"), "title": _txt(v.findtext("TITLE"), 300), "sev": _int(v.findtext("SEVERITY_LEVEL")),
        "solution": _txt(v.findtext("SOLUTION"), 2000), "threat": _txt(v.findtext("DIAGNOSIS"), 600),
        "category": _txt(v.findtext("CATEGORY"), 80), "rti": rti, "patchable": v.findtext("PATCHABLE") == "1",
        "published": v.findtext("PUBLISHED_DATETIME") or "", "patchReleased": "",
        # CVSS comes back only when "CVSS Scoring" is switched on for the Qualys subscription; 0 = not supplied
        "cvss": _num(v.findtext("CVSS_V3/BASE")) or _num(v.findtext("CVSS/BASE")),
        "cveCount": len(cves), "cves": cves[:1000],     # all of them in practice (v4.14 CVE Lookup searches this list)
    }


def normalise_detection(d):
    """Compact list: [qid, type, sev, status, proto, port, qds, first, last, times, lastFixed]."""
    return [d.findtext("QID"), d.findtext("TYPE") or "", _int(d.findtext("SEVERITY")),
            STATUS.get((d.findtext("STATUS") or "").lower(), (d.findtext("STATUS") or "").upper()),
            (d.findtext("PROTOCOL") or "").lower(), d.findtext("PORT") or "", _int(d.findtext("QDS")),
            d.findtext("FIRST_FOUND_DATETIME") or "", d.findtext("LAST_FOUND_DATETIME") or "",
            _int(d.findtext("TIMES_FOUND")), d.findtext("LAST_FIXED_DATETIME") or ""]


# ------------------------------------------------------------------ the sync job

_job_lock = threading.Lock()
_job = {"running": False}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _meta(cur, kind):
    cur.execute("SELECT doc FROM qualys WHERE kind='meta' AND k=%s", (kind,))
    r = cur.fetchone()
    return json.loads(r[0]) if r else None


def _put_meta(cur, kind, doc):
    cur.execute("REPLACE INTO qualys (kind, k, doc) VALUES ('meta', %s, %s)", (kind, json.dumps(doc)))


def blocked():
    """The refused-login record, when it is for the login set now."""
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            a = _meta(cur, "authfail")
    except Exception:
        return None
    return a if a and a.get("fp") == fingerprint() else None


def status():
    out = {"configured": configured(), "scope": TAG, "scheduleHour": HOUR if 0 <= HOUR <= 23 else None,
           "apiHost": urllib.parse.urlsplit(API).hostname if API else "", "job": dict(_job)}
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            if not _job.get("started"):         # nothing in this process yet (after a restart): the saved one
                out["job"] = _meta(cur, "job") or {"running": False}
            for k in ("last", "err", "applied", "claim"):
                out[{"err": "error"}.get(k, k)] = _meta(cur, k)
            a = _meta(cur, "authfail")
            out["blocked"] = bool(a and a.get("fp") == fingerprint())
    except Exception as e:                              # table missing on a brand new database, etc.
        out["dbError"] = str(e)[:200]
    return out


def start(user):
    """Start a sync in the background. False if one is running already."""
    if not configured():
        raise QxError("setup", "Qualys is not set up on this server. Run ./deploy.sh qualys url URL, then qualys user and qualys pass")
    if blocked():
        raise QxError("blocked", "Syncs are stopped because Qualys refused the login. Fix it with ./deploy.sh qualys pass "
                                 "(or ./deploy.sh qualys unblock).")
    if not _job_lock.acquire(blocking=False):
        return False
    eta = None
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            last = _meta(cur, "last")
            eta = (last or {}).get("seconds")
            if last and last.get("scope", "") != TAG:
                eta = None                      # a different scope takes a different time
    except Exception:
        pass
    _job.clear()
    _job.update({"running": True, "by": user, "started": now_iso(), "phase": "starting", "count": 0, "total": None,
                 "scope": TAG, "calls": 0, "rate": None, "etaSeconds": eta, "log": [],
                 "steps": [{"key": k, "label": lbl, "state": "waiting", "count": 0, "total": None, "seconds": None} for k, lbl in STEPS]})
    _log("info", f"Sync started by {user} ({TAG or 'every host'})")
    threading.Thread(target=_run, args=(user,), name="qualys-sync", daemon=True).start()
    return True


# ---- progress: the job document (steps, counts, log, calls, Qualys's remaining allowance) is kept in memory and
# saved to the database every few seconds, so the page and `qualys.py watch` (another process) can follow it.
_last_save = [0.0]


def _persist(force=False):
    if not force and time.time() - _last_save[0] < 2:
        return
    _last_save[0] = time.time()
    _job["beat"] = now_iso()
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            _put_meta(cur, "job", _job)
    except Exception:
        pass


def _log(level, msg):
    """level: info | retry | wait | warn | error. Also printed to the container log (./deploy.sh logs)."""
    print(f"[qualys] {level}: {msg}", flush=True)
    if not _job.get("running"):
        return
    log = _job.setdefault("log", [])
    log.append({"at": now_iso(), "level": level, "msg": str(msg)[:300]})
    del log[:-60]
    _persist(level != "info")


def _rate(headers):
    _job["calls"] = _calls[0]
    try:
        if headers.get("X-RateLimit-Remaining") is not None:
            _job["rate"] = {"remaining": int(headers.get("X-RateLimit-Remaining")), "limit": int(headers.get("X-RateLimit-Limit") or 0),
                            "window": int(headers.get("X-RateLimit-Window-Sec") or 0), "at": now_iso()}
    except (TypeError, ValueError):
        pass


def _step(key, count=0, total=None):
    """Finish the running step and start `key`."""
    now = time.time()
    for st in _job.get("steps", []):
        if st["state"] == "running":
            st.update(state="done", seconds=round(now - st["t0"], 1))
    label = key
    for st in _job.get("steps", []):
        if st["key"] == key:
            st.update(state="running", t0=now, count=count, total=total)
            label = st["label"]
    _job.update(phase=label, count=count, total=total)
    _log("info", f"{label}…")
    _persist(True)


def _progress(count, total=None):
    for st in _job.get("steps", []):
        if st["state"] == "running":
            st["count"] = count
            if total is not None:
                st["total"] = total
    _job.update(count=count, total=total if total is not None else _job.get("total"), calls=_calls[0])
    _persist()


def _phase(name, count=0, total=None):        # used by the fetch_* functions: progress within the current step
    _progress(count, total)


def _steps_summary(j):
    return [{"label": st["label"], "state": st["state"], "seconds": st.get("seconds"), "count": st.get("count"),
             "total": st.get("total")} for st in j.get("steps", [])]


def _history_doc(j, ok, result=None, error=None):
    r = result or {}
    k = r.get("syncId") or ((j.get("started") or now_iso()).replace("-", "").replace(":", "") + "-failed")
    return {"id": k, "ok": ok, "started": j.get("started"), "finished": j.get("finished") or now_iso(), "by": j.get("by"),
            "scope": r.get("scope", TAG), "seconds": r.get("seconds"), "calls": j.get("calls", _calls[0]),
            "hosts": r.get("hosts"), "detections": r.get("detections"), "qids": r.get("qids"), "scores": r.get("scores"),
            "changes": r.get("changes"), "warnings": r.get("warnings") or [], "error": error or j.get("error"),
            "steps": _steps_summary(j), "rate": j.get("rate")}


def _put_history(cur, doc):
    cur.execute("REPLACE INTO qualys (kind, k, doc) VALUES ('hist', %s, %s)", (doc["id"][:80], json.dumps(doc)))
    cur.execute("SELECT k FROM qualys WHERE kind='hist' ORDER BY k DESC LIMIT %s, 1000", (HISTORY_KEEP,))
    old = [r[0] for r in cur.fetchall()]
    for k in old:
        cur.execute("DELETE FROM qualys WHERE kind='hist' AND k=%s", (k,))


def history(limit=HISTORY_KEEP):
    with _conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT doc FROM qualys WHERE kind='hist' ORDER BY k DESC LIMIT %s", (limit,))
        return [json.loads(r[0]) for r in cur.fetchall()]


def _run(user):
    t0 = time.time()
    _calls[0] = 0
    try:
        result = sync(user, t0)
        now = time.time()
        for st in _job.get("steps", []):
            if st["state"] == "running":
                st.update(state="done", seconds=round(now - st["t0"], 1))
        result.update(seconds=round(now - t0), calls=_calls[0], steps=_steps_summary(_job))
        _job.update(finished=now_iso(), calls=_calls[0])
        ch = result.get("changes") or {}
        _log("info", f"Done in {result['seconds']} s: {result['hosts']} hosts, {result['detections']} findings, "
                     f"{result['qids']} QIDs, {result['calls']} calls"
                     + (f"; since the last sync {ch.get('newOpen', 0)} new open findings, {ch.get('closed', 0)} no longer open" if ch else ""))
        with _conn_ctx() as c, c.cursor() as cur:
            _put_meta(cur, "last", result)
            _put_history(cur, _history_doc(_job, ok=True, result=result))
            _audit(cur, user, "qualys-sync", f"{result['hosts']} hosts, {result['detections']} findings, "
                                             f"{result['qids']} QIDs, {result['calls']} calls")
    except Exception as e:
        kind = e.kind if isinstance(e, QxError) else "error"
        msg = str(e) if isinstance(e, QxError) else f"{type(e).__name__}: {str(e)[:300]}"
        try:
            with _conn_ctx() as c, c.cursor() as cur:
                _put_meta(cur, "err", {"at": now_iso(), "by": user, "kind": kind, "message": msg, "phase": _job.get("phase")})
                _audit(cur, user, "qualys-sync-failed", msg)
        except Exception:
            pass
        _job.update({"error": msg, "errorKind": kind, "finished": now_iso(), "calls": _calls[0]})
        for st in _job.get("steps", []):
            if st["state"] == "running":
                st.update(state="failed", seconds=round(time.time() - st["t0"], 1))
        _log("error", msg)
        try:
            with _conn_ctx() as c, c.cursor() as cur:
                _put_history(cur, _history_doc(_job, ok=False, error=msg))
        except Exception:
            pass
    finally:
        _job.update({"running": False, "finished": _job.get("finished") or now_iso()})
        _persist(True)
        _job_lock.release()


def fetch_hosts():
    """Hosts in scope, with the CSAM asset id and the last VM scan date."""
    hosts, id_min = {}, None
    while True:
        p = _scope({"action": "list", "details": "All", "show_asset_id": 1, "truncation_limit": 1000})
        if id_min:
            p["id_min"] = id_min
        root = vm("/api/2.0/fo/asset/host/", p, "host list")
        for h in root.findall(".//HOST_LIST/HOST"):
            hid = h.findtext("ID")
            hosts[hid] = {"id": hid, "a": h.findtext("ASSET_ID") or "", "ip": h.findtext("IP") or "",
                          "dns": h.findtext("DNS") or "", "nb": h.findtext("NETBIOS") or "", "os": h.findtext("OS") or "",
                          "track": h.findtext("TRACKING_METHOD") or "",
                          "scan": h.findtext("LAST_VULN_SCAN_DATETIME") or h.findtext("LAST_VM_SCANNED_DATE") or "", "d": []}
        _phase("hosts", len(hosts))
        id_min = _next_id(root)
        if not id_min:
            return hosts


def fetch_detections(hosts):
    count, id_min = 0, None
    while True:
        p = _scope({"action": "list", "truncation_limit": HOSTS_PER_PAGE, "show_results": 0, "show_qds": 1,
                    "show_asset_id": 1, "status": "New,Active,Re-Opened,Fixed"})
        if id_min:
            p["id_min"] = id_min
        root = vm("/api/2.0/fo/asset/host/vm/detection/", p, "detections")
        for h in root.findall(".//HOST_LIST/HOST"):
            hid = h.findtext("ID")
            x = hosts.get(hid)
            if x is None:                 # in the detection list but not in the host list (scope changed mid-sync)
                x = hosts[hid] = {"id": hid, "a": h.findtext("ASSET_ID") or "", "ip": h.findtext("IP") or "",
                                  "dns": h.findtext("DNS") or "", "nb": h.findtext("NETBIOS") or "", "os": h.findtext("OS") or "",
                                  "track": h.findtext("TRACKING_METHOD") or "", "scan": h.findtext("LAST_SCAN_DATETIME") or "", "d": []}
            for d in h.findall("./DETECTION_LIST/DETECTION"):
                x["d"].append(normalise_detection(d))
                count += 1
        _phase("findings", count)
        id_min = _next_id(root)
        if not id_min:
            return count


def fetch_kb(qids):
    out, ql = {}, sorted(qids, key=lambda q: _int(q))
    for i in range(0, len(ql), KB_BATCH):
        _phase("KnowledgeBase", i, len(ql))
        root = vm("/api/2.0/fo/knowledge_base/vuln/", {"action": "list", "details": "All",
                                                       "ids": ",".join(ql[i:i + KB_BATCH])}, "KnowledgeBase")
        for v in root.findall(".//VULN_LIST/VULN"):
            k = normalise_kb(v)
            out[k["qid"]] = k
    return out


def fetch_scores(warnings):
    """TruRisk, asset criticality and tags from CSAM, by asset id. On failure the sync goes on without them."""
    out, last = {}, None
    body = {"filters": [{"field": "tags.name", "operator": "EQUALS", "value": TAG}]} if TAG else {"filters": []}
    try:
        for _ in range(200):
            q = f"?pageSize={CSAM_PAGE}&includeFields=assetId,assetName,riskScore,criticality,tagList"
            if last:
                q += f"&lastSeenAssetId={last}"
            r = gateway("/rest/2.0/search/am/asset" + q, body, "asset scores")
            for a in ((r.get("assetListData") or {}).get("asset") or []):
                crit = a.get("criticality") or {}
                tags = [t.get("tagName") for t in ((a.get("tagList") or {}).get("tag") or []) if t.get("tagName")]
                out[str(a.get("assetId"))] = {"n": a.get("assetName") or "", "tr": a.get("riskScore"),
                                              "cr": crit.get("score"), "crd": bool(crit.get("isDefault")),
                                              "tags": ",".join(tags)[:2000]}
            _phase("asset scores", len(out))
            last = r.get("lastSeenAssetId")
            if not r.get("hasMore") or not last:
                return out
        warnings.append("Asset scores: stopped after 200 pages")
    except QxError as e:
        if e.kind == "auth":
            raise
        warnings.append(f"Asset scores (TruRisk, criticality) not loaded: {e}")
    return out


def sync(user, t0=None):
    warnings = []
    _step("hosts")
    hosts = fetch_hosts()
    _step("findings")
    total = fetch_detections(hosts)
    qids = {d[0] for h in hosts.values() for d in h["d"]}
    _step("kb", 0, len(qids))
    kb = fetch_kb(qids)
    missing = len(qids - set(kb))
    if missing:
        warnings.append(f"{missing} QIDs were not in the KnowledgeBase reply")
    _step("scores")
    scores = fetch_scores(warnings)
    for w in warnings:
        _log("warn", w)

    _step("save")
    changes = _changes(hosts)
    sync_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rows, chunk, n = [], [], 0
    for h in hosts.values():
        s = scores.get(h["a"]) or {}
        h.update({"n": s.get("n") or h["dns"] or h["nb"] or h["ip"], "tr": s.get("tr"), "cr": s.get("cr"),
                  "crd": s.get("crd"), "tags": s.get("tags", "")})
        chunk.append(h)
        if len(chunk) >= CHUNK_HOSTS:
            rows.append(("pkg", f"{sync_id}:{n:05d}", json.dumps(chunk, separators=(",", ":"))))
            chunk, n = [], n + 1
    if chunk:
        rows.append(("pkg", f"{sync_id}:{n:05d}", json.dumps(chunk, separators=(",", ":"))))
    scanned = sum(1 for h in hosts.values() if h["scan"])
    result = {"syncId": sync_id, "at": now_iso(), "by": user, "scope": TAG, "hosts": len(hosts), "scanned": scanned,
              "withFindings": sum(1 for h in hosts.values() if h["d"]), "detections": total, "qids": len(kb),
              "scores": len(scores), "warnings": warnings, "complete": True, "changes": changes,
              "seconds": round(time.time() - t0) if t0 else None, "calls": _calls[0]}
    # Publish in one transaction: the new KnowledgeBase + package rows and the 'last' pointer, old package rows out.
    with _conn_ctx() as c, c.cursor() as cur:
        cur.execute("DELETE FROM qualys WHERE kind='kb'")
        kb_rows = [("kb", q, json.dumps(v, separators=(",", ":"))) for q, v in kb.items()]
        for i in range(0, len(kb_rows), 500):
            cur.executemany("INSERT INTO qualys (kind, k, doc) VALUES (%s,%s,%s)", kb_rows[i:i + 500])
        for r in rows:
            cur.execute("INSERT INTO qualys (kind, k, doc) VALUES (%s,%s,%s)", r)
        cur.execute("DELETE FROM qualys WHERE kind='pkg' AND k NOT LIKE %s", (sync_id + ":%",))
        _put_meta(cur, "last", result)
        cur.execute("DELETE FROM qualys WHERE kind='meta' AND k='err'")
    return result


def _open_keys(hosts):
    return {(h["id"], d[0], d[4], d[5]) for h in hosts for d in h["d"] if d[3] != "FIXED"}


def _changes(hosts):
    """What changed since the previous sync: open findings that are new / no longer open, hosts added / gone."""
    try:
        with _conn_ctx() as c, c.cursor() as cur:
            prev = _meta(cur, "last")
            if not prev:
                return None
            cur.execute("SELECT doc FROM qualys WHERE kind='pkg' AND k LIKE %s", (prev["syncId"] + ":%",))
            before = [h for (doc,) in cur.fetchall() for h in json.loads(doc)]
    except Exception:
        return None
    now_open, was_open = _open_keys(hosts.values()), _open_keys(before)
    now_h, was_h = set(hosts), {h["id"] for h in before}
    return {"since": prev["syncId"], "sameScope": prev.get("scope", "") == TAG, "open": len(now_open),
            "newOpen": len(now_open - was_open), "closed": len(was_open - now_open),
            "hostsAdded": len(now_h - was_h), "hostsGone": len(was_h - now_h)}


def data_stream():
    """The latest published sync for the page: meta, the KnowledgeBase entries and the hosts with their findings."""
    with _conn_ctx() as c, c.cursor() as cur:
        last = _meta(cur, "last")
    yield '{"meta":' + json.dumps(last) + ',"qids":['
    if not last:
        yield '],"hosts":[]}'
        return
    with _conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT doc FROM qualys WHERE kind='kb'")
        first = True
        for (doc,) in cur.fetchall():
            yield doc if first else "," + doc
            first = False
        yield '],"hosts":['
        cur.execute("SELECT doc FROM qualys WHERE kind='pkg' AND k LIKE %s ORDER BY k", (last["syncId"] + ":%",))
        first = True
        for (doc,) in cur.fetchall():
            inner = doc[1:-1]                 # each row is a JSON list of hosts: splice the lists together
            if inner:
                yield inner if first else "," + inner
                first = False
    yield "]}"


def claim(user, sync_id, page=""):
    """One editor applies each sync: returns (True, None) to go ahead, or (False, reason)."""
    with _conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT doc FROM qualys WHERE kind='meta' AND k='last' FOR UPDATE")
        r = cur.fetchone()
        last = json.loads(r[0]) if r else None
        if not last or last.get("syncId") != sync_id:
            return False, "That sync is no longer the latest one"
        applied = _meta(cur, "applied")
        if applied and applied.get("syncId") == sync_id:
            return False, f"Already applied by {applied.get('by')} at {applied.get('at')}"
        cl = _meta(cur, "claim")
        if cl and cl.get("syncId") == sync_id and (cl.get("page") or cl.get("by")) != (page or user):
            age = time.time() - datetime.strptime(cl["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            if age < CLAIM_MINUTES * 60:
                return False, f"{cl.get('by')} is applying it now"
        _put_meta(cur, "claim", {"syncId": sync_id, "by": user, "page": page, "at": now_iso()})
    return True, None


def applied(user, sync_id, summary):
    with _conn_ctx() as c, c.cursor() as cur:
        cl = _meta(cur, "claim")
        if not cl or cl.get("syncId") != sync_id:
            return False
        _put_meta(cur, "applied", {"syncId": sync_id, "by": user, "at": now_iso(), "summary": summary})
        cur.execute("DELETE FROM qualys WHERE kind='meta' AND k='claim'")
        cur.execute("SELECT doc FROM qualys WHERE kind='hist' AND k=%s", (sync_id,))
        r = cur.fetchone()
        if r:
            h = json.loads(r[0])
            h["applied"] = {"by": user, "at": now_iso(), "seconds": summary.get("seconds"), "assets": summary.get("assets"),
                            "unrecognised": summary.get("unrecognised")}
            cur.execute("UPDATE qualys SET doc=%s WHERE kind='hist' AND k=%s", (json.dumps(h), sync_id))
        _audit(cur, user, "qualys-apply", f"sync {sync_id}: {json.dumps(summary)[:300]}")
    return True


def due(now=None):
    """True when the daily sync should run: past QUALYS_SYNC_HOUR (UTC) and no sync or failure yet today."""
    now = now or datetime.now(timezone.utc)
    if not (0 <= HOUR <= 23) or now.hour < HOUR or _job.get("running") or blocked():
        return False
    with _conn_ctx() as c, c.cursor() as cur:
        last, err = _meta(cur, "last"), _meta(cur, "err")
    today = now.strftime("%Y-%m-%d")
    return not any(x and str(x.get("at", "")).startswith(today) for x in (last, err))


def _scheduler():
    """Once a day at QUALYS_SYNC_HOUR (UTC); a failed day is not retried until the next day (protects the login)."""
    time.sleep(120)
    while True:
        try:
            if due():
                start("schedule")
        except Exception:
            pass
        time.sleep(300)


# ------------------------------------------------------------------ command line

def _cli_test():
    if not configured():
        print("Qualys is not set up: QUALYS_API_URL, QUALYS_USERNAME and QUALYS_PASSWORD_B64 are needed")
        return 1
    print(f"API {API}   gateway {GATEWAY}   user {USER}   scope: {TAG or 'every host'}")
    if blocked():
        print("BLOCKED: Qualys refused this login earlier. Set the password again (./deploy.sh qualys pass) or "
              "./deploy.sh qualys unblock")
        return 2
    try:
        root = vm("/api/2.0/fo/asset/host/", _scope({"action": "list", "details": "Basic", "truncation_limit": 5}), "host list")
        print(f"login OK; hosts on a first small page: {len(root.findall('.//HOST_LIST/HOST'))}"
              f"{' (more pages)' if _next_id(root) else ''}")
        root = vm("/api/2.0/fo/asset/host/vm/detection/", _scope({"action": "list", "truncation_limit": 1, "show_results": 0,
                                                                   "show_qds": 1}), "detections")
        print(f"detection API OK; findings on the first host: {len(root.findall('.//DETECTION'))}")
        body = {"filters": [{"field": "tags.name", "operator": "EQUALS", "value": TAG}]} if TAG else {"filters": []}
        r = gateway("/rest/2.0/search/am/asset?pageSize=1&includeFields=assetId,riskScore", body, "asset scores")
        print(f"gateway OK; asset scores answer: {r.get('responseMessage') or r.get('responseCode')}")
        return 0
    except QxError as e:
        print(f"FAILED ({e.kind}): {e}")
        return 2


def _fmt_secs(s):
    s = int(s or 0)
    return f"{s // 60} min {s % 60:02d} s" if s >= 60 else f"{s} s"


def _cli_watch():
    """Follow the running sync (or wait for the next one) and print each step, the log and the progress."""
    def snap():
        with _conn_ctx() as c, c.cursor() as cur:
            return _meta(cur, "job") or {}, _meta(cur, "last"), _meta(cur, "applied")
    print(f"Qualys sync: {TAG or 'every host'}, " + (f"daily at {HOUR:02d}:00 UTC" if 0 <= HOUR <= 23 else "on demand only"))
    following, seen, line, waiting, printed = None, 0, "", False, 0.0
    try:
        while True:
            job, last, applied_ = snap()
            beat = job.get("beat") or job.get("started") or ""
            stale = job.get("running") and beat and (datetime.now(timezone.utc) - datetime.strptime(beat, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)).total_seconds() > 600
            if job.get("running") and not stale:
                if following != job.get("started"):
                    following, seen, line, printed = job.get("started"), 0, "", 0.0
                    eta = f" (the last one took {_fmt_secs(job['etaSeconds'])})" if job.get("etaSeconds") else ""
                    print(f"\n== Sync started {job.get('started')} by {job.get('by')}{eta}")
                for e in (job.get("log") or [])[seen:]:
                    if e["level"] != "info" or not e["msg"].endswith("…"):
                        print(f"   {e['at'][11:19]} {e['level'].upper():5} {e['msg']}")
                seen = len(job.get("log") or [])
                cur_ = next((x for x in job.get("steps", []) if x["state"] == "running"), None)
                done = " ".join(f"{x['label']} ✓" for x in job.get("steps", []) if x["state"] == "done")
                el = (datetime.now(timezone.utc) - datetime.strptime(job["started"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)).total_seconds()
                prog = ""
                if cur_:
                    prog = f"⟳ {cur_['label']} {cur_.get('count') or 0:,}" + (f" of {cur_['total']:,} ({100 * (cur_.get('count') or 0) // max(1, cur_['total'])}%)" if cur_.get("total") else "")
                rate = job.get("rate") or {}
                new = (f"{done}  {prog}  · calls {job.get('calls', 0)}"
                       + (f" · Qualys allows {rate['remaining']} more this hour" if rate.get("remaining") is not None else ""))
                if new != line or time.time() - printed > 30:    # on a change, or every 30 s so you can see it is alive
                    print(f"   [{_fmt_secs(el)}] {new}")
                    line, printed = new, time.time()
            elif following:                       # the sync we were following has finished
                for e in (job.get("log") or [])[seen:]:
                    print(f"   {e['at'][11:19]} {e['level'].upper():5} {e['msg']}")
                if job.get("error"):
                    print(f"== FAILED: {job['error']}")
                    return 2
                print("== Finished. Steps: " + ", ".join(f"{x['label']} {_fmt_secs(x.get('seconds'))}" for x in job.get("steps", [])))
                if last and not (applied_ and applied_.get("syncId") == last.get("syncId")):
                    print("   The first editor to open the portal (or the page that pressed Sync) applies it.")
                return 0
            elif not waiting:
                if last:
                    ap = f", applied by {applied_['by']} at {applied_['at']}" if applied_ and applied_.get("syncId") == last.get("syncId") else ", not applied yet"
                    print(f"Last sync {last.get('at')}: {last.get('hosts')} hosts, {last.get('detections')} findings, {last.get('calls')} calls, {_fmt_secs(last.get('seconds'))}{ap}")
                if stale:
                    print("The last sync stopped without finishing (the portal restarted?).")
                print("No sync is running. Waiting for one to start (Sync from Qualys on the Vulnerability Management page, or the daily run). Ctrl+C to stop.")
                waiting = True
            time.sleep(2)
    except KeyboardInterrupt:
        print()
        return 0


def _cli_unblock():
    with _conn_ctx() as c, c.cursor() as cur:
        cur.execute("DELETE FROM qualys WHERE kind='meta' AND k='authfail'")
    print("unblocked: syncs may run again")
    return 0


if __name__ == "__main__":
    if sys.argv[1:2] in (["test"], ["unblock"], ["watch"]):
        # Standalone: connect to the database the same way app.py does.
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import app as _app
        _conn_ctx, _audit = _app.conn_ctx, _app.audit
        _app.migrate()
        sys.exit({"test": _cli_test, "unblock": _cli_unblock, "watch": _cli_watch}[sys.argv[1]]())
    print(__doc__)
