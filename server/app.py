"""CyberView API: serves the single-page app and stores its data in MariaDB.

Small collections (register, review queue, ...) are stored one JSON document per row in `records`.
Vulnerability detections and the QID catalogue have their own indexed tables.
Users, roles (viewer / editor / admin) and sessions live in the database. While there are NO users the portal is
open ("setup mode", everyone is an administrator) so the first administrator can be created from the Users page.
"""
import hashlib
import hmac
import json
import os
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

import pymysql
from fastapi import Body, FastAPI, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

import automox
import eol
import redhat
import qualys

VERSION = "4.22.2"
STATIC_DIR = Path(os.environ.get("STATIC_DIR", "/app/static"))
COOKIE = "portal_session"
SESSION_IDLE = timedelta(hours=12)
SESSION_MAX = timedelta(days=7)
LOCK_AFTER, LOCK_FOR = 5, timedelta(minutes=15)
MIN_PASSWORD = 10
RANK = {"viewer": 1, "editor": 2, "admin": 3}
# backup-file field -> collection
FIELD_MAP = {
    "assetRegister": "gov_asset_register", "reviewQueue": "gov_review_queue", "ownershipLedger": "gov_ownership_ledger",
    "platformInventory": "gov_platform_inventory", "vulnAssetSummary": "gov_vuln_asset_summary",
    "vulnServiceSummary": "gov_vuln_service_summary", "vulnCveSummary": "gov_vuln_cve_summary",
    "vulnDetails": "gov_vuln_details", "vulnMeta": "gov_vuln_meta", "riskAcceptances": "gov_risk_acceptances",
    "eolDates": "gov_eol_dates", "remediation": "gov_remediation", "remediationSettings": "gov_remediation_settings",
    "automoxLinks": "gov_automox_links", "statusSettings": "gov_status_settings", "statusHistory": "gov_status_history", "scanDates": "gov_scan_dates",
    "orgSettings": "gov_org_settings", "planForecast": "gov_plan_forecast", "cveWatch": "gov_cve_watch",
}
# collections whose edits are written to the change history, and the field that identifies a record
TRACKED = {"gov_asset_register": ("normalizedName", "normalizedName"), "gov_risk_acceptances": ("id", "asset"),
           "gov_remediation": ("id", "id")}

# The keys the front end uses; anything else is refused.
COLLECTIONS = {
    "gov_asset_register", "gov_review_queue", "gov_ownership_ledger", "gov_platform_inventory",
    "gov_vuln_asset_summary", "gov_vuln_service_summary", "gov_vuln_cve_summary", "gov_vuln_details",
    "gov_vuln_meta", "gov_risk_acceptances", "gov_eol_dates", "gov_remediation", "gov_remediation_settings",
    "gov_automox_links", "gov_status_settings", "gov_status_history", "gov_scan_dates", "gov_org_settings", "gov_plan_forecast",
    "gov_cve_watch",
}
# Saved one record at a time through /api/tasks, never as a whole collection (a stale page would wipe other people's work).
PER_RECORD = {"gov_remediation"}

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS collections (
        name VARCHAR(40) NOT NULL PRIMARY KEY,
        kind ENUM('array','object') NOT NULL,
        revision INT NOT NULL DEFAULT 0,
        updated_at DATETIME(3) NOT NULL,
        updated_by VARCHAR(100) NOT NULL DEFAULT ''
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS records (
        collection VARCHAR(40) NOT NULL,
        seq INT NOT NULL,
        doc LONGTEXT NOT NULL,
        PRIMARY KEY (collection, seq),
        CONSTRAINT records_json CHECK (JSON_VALID(doc))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS detections (
        k VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL PRIMARY KEY,
        asset VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
        qid VARCHAR(20) NOT NULL,
        sev TINYINT NOT NULL DEFAULT 0,
        qvs FLOAT NOT NULL DEFAULT 0,
        doc LONGTEXT NOT NULL,
        KEY idx_asset (asset),
        KEY idx_qid (qid)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS qids (
        qid VARCHAR(20) NOT NULL PRIMARY KEY,
        doc LONGTEXT NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS users (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(60) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL UNIQUE,
        pw_hash VARCHAR(250) NOT NULL,
        role ENUM('viewer','editor','admin') NOT NULL DEFAULT 'editor',
        disabled TINYINT(1) NOT NULL DEFAULT 0,
        must_change TINYINT(1) NOT NULL DEFAULT 0,
        failed_attempts INT NOT NULL DEFAULT 0,
        locked_until DATETIME NULL,
        created_at DATETIME NOT NULL,
        last_login DATETIME NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS sessions (
        token_hash CHAR(64) NOT NULL PRIMARY KEY,
        user_id INT NOT NULL,
        created_at DATETIME NOT NULL,
        last_seen DATETIME NOT NULL,
        KEY idx_user (user_id),
        CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS change_log (
        id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        at DATETIME(3) NOT NULL,
        user VARCHAR(100) NOT NULL,
        collection VARCHAR(40) NOT NULL,
        record_key VARCHAR(255) NOT NULL,
        action ENUM('add','change','remove','bulk') NOT NULL,
        changes LONGTEXT NULL,
        KEY idx_at (at),
        KEY idx_record (record_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS audit_log (
        id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        at DATETIME(3) NOT NULL,
        user VARCHAR(100) NOT NULL,
        action VARCHAR(60) NOT NULL,
        detail VARCHAR(500) NOT NULL DEFAULT '',
        KEY idx_at (at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
]


def db_settings():
    return dict(
        host=os.environ.get("DB_HOST", "db"), port=int(os.environ.get("DB_PORT", "3306")),
        user=os.environ.get("DB_USER", "qualys"), password=os.environ.get("DB_PASSWORD", ""),
        database=os.environ.get("DB_NAME", "qualys"), charset="utf8mb4", autocommit=False,
    )


def connect(**extra):
    return pymysql.connect(**{**db_settings(), **extra})


@contextmanager
def conn_ctx(**extra):
    c = connect(**extra)
    try:
        yield c
        c.commit()
    except BaseException:
        c.rollback()
        raise
    finally:
        c.close()


def migrate(wait_seconds=90):
    deadline = time.time() + wait_seconds
    while True:
        try:
            with conn_ctx() as c, c.cursor() as cur:
                for stmt in SCHEMA + [automox.SCHEMA, qualys.SCHEMA, eol.SCHEMA, redhat.SCHEMA]:
                    cur.execute(stmt)
            return
        except pymysql.err.OperationalError:
            if time.time() > deadline:
                raise
            time.sleep(2)


app = FastAPI(title="CyberView", version=VERSION, docs_url=None, redoc_url=None, openapi_url=None)


@app.on_event("startup")
def _startup():
    migrate()
    automox.init(conn_ctx, audit)
    qualys.init(conn_ctx, audit)
    eol.init(conn_ctx, audit)
    redhat.init(conn_ctx, audit)


# ------------------------------------------------------------------ users, sessions, roles

_ip_fails = {}  # ip -> [timestamps]: a coarse brake on password guessing across many usernames


def hash_password(password, salt=None, iterations=600_000):
    salt = salt or os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{iterations}:{salt.hex()}:{h.hex()}"


def check_password(stored, password):
    try:
        iterations, salt, want = stored.split(":")
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(got.hex(), want)
    except ValueError:
        return False


_DUMMY_HASH = hash_password("not-a-real-password")


def validate_new_password(username, password):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise HTTPException(400, f"Use a password of at least {MIN_PASSWORD} characters")
    if password.lower() == (username or "").lower():
        raise HTTPException(400, "The password must not be the user name")


def validate_username(name):
    import re
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._@-]{1,60}", name):
        raise HTTPException(400, "User names use letters, digits and . _ @ - (up to 60)")


def create_user(cur, username, password, role="editor", must_change=False):
    validate_username(username)
    validate_new_password(username, password)
    if role not in RANK:
        raise HTTPException(400, "Role must be viewer, editor or admin")
    cur.execute("SELECT 1 FROM users WHERE username=%s", (username,))
    if cur.fetchone():
        raise HTTPException(409, "That user name is already taken")
    cur.execute("INSERT INTO users (username, pw_hash, role, must_change, created_at) VALUES (%s,%s,%s,%s,NOW())",
                (username, hash_password(password), role, 1 if must_change else 0))
    return cur.lastrowid


def active_admins(cur, excluding=None):
    cur.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0" + (" AND username<>%s" if excluding else ""),
                (excluding,) if excluding else ())
    return cur.fetchone()[0]


def sha(token):
    return hashlib.sha256(token.encode()).hexdigest()


def resolve_user(token):
    """Return the signed-in user for a session cookie, the setup-mode admin when there are no users, or None."""
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            return {"name": "anonymous", "role": "admin", "open": True, "mustChange": False}
        if not token:
            return None
        h = sha(token)
        cur.execute(
            "SELECT u.id, u.username, u.role, u.disabled, u.must_change, s.last_seen < NOW() - INTERVAL 1 MINUTE "
            "FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash=%s AND s.last_seen > NOW() - INTERVAL 12 HOUR AND s.created_at > NOW() - INTERVAL 7 DAY", (h,))
        row = cur.fetchone()
        if not row or row[3]:
            return None
        if row[5]:
            cur.execute("UPDATE sessions SET last_seen=NOW() WHERE token_hash=%s", (h,))
        return {"name": row[1], "role": row[2], "open": False, "mustChange": bool(row[4]), "id": row[0], "token": h}


def required_role(method, path):
    if path.startswith("/api/users") or path in ("/api/restore", "/api/audit"):
        return "admin"
    if method == "DELETE":
        return "admin"
    if path in ("/api/whoami", "/api/logout", "/api/me/password") or method in ("GET", "HEAD"):
        return "viewer"
    return "editor"


OPEN_PATHS = {"/api/health", "/api/login"}
MUST_CHANGE_OK = {"/api/whoami", "/api/logout", "/api/me/password"}


def current_user(request: Request):
    u = getattr(request.state, "user", None)
    return u["name"] if u else "anonymous"


def login_page():
    return FileResponse(STATIC_DIR / "login.html", headers={"Cache-Control": "no-store"})


@app.middleware("http")
async def authenticate(request: Request, call_next):
    path, method = request.url.path, request.method
    request.state.user = None
    if path in OPEN_PATHS:
        return await call_next(request)
    user = await run_in_threadpool(resolve_user, request.cookies.get(COOKIE))
    if user is None:
        if path.startswith("/api/"):
            return JSONResponse({"error": "login"}, status_code=401)
        return login_page()
    request.state.user = user
    if path.startswith("/api/"):
        if method not in ("GET", "HEAD") and request.headers.get("x-requested-with") != "portal":
            return JSONResponse({"error": "Missing X-Requested-With header"}, status_code=403)
        if user["mustChange"] and path not in MUST_CHANGE_OK:
            return JSONResponse({"error": "You must choose a new password first"}, status_code=403)
        if RANK[user["role"]] < RANK[required_role(method, path)]:
            return JSONResponse({"error": "Your role does not allow this"}, status_code=403)
    return await call_next(request)


def audit(cur, user, action, detail=""):
    cur.execute("INSERT INTO audit_log (at, user, action, detail) VALUES (NOW(3), %s, %s, %s)", (user, action, detail[:500]))


def set_session(response, request, user_id, cur):
    token = secrets.token_urlsafe(32)
    cur.execute("DELETE FROM sessions WHERE last_seen < NOW() - INTERVAL 7 DAY")
    cur.execute("INSERT INTO sessions (token_hash, user_id, created_at, last_seen) VALUES (%s,%s,NOW(),NOW())", (sha(token), user_id))
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=secure, path="/", max_age=int(SESSION_MAX.total_seconds()))


# ------------------------------------------------------------------ pages and sign-in

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/api/health")
def health():
    try:
        with conn_ctx() as c, c.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users")
            n = cur.fetchone()[0]
    except Exception as e:
        return JSONResponse({"app": "qualys-portal", "ok": False, "error": str(e)[:200]}, status_code=503)
    return {"app": "qualys-portal", "ok": True, "version": VERSION, "users": n}


@app.get("/api/whoami")
def whoami(request: Request):
    u = request.state.user
    return {"user": u["name"], "role": u["role"], "open": u["open"], "mustChange": u["mustChange"]}


@app.post("/api/login")
def login(request: Request, response: Response, body: dict = Body(...)):
    ip = request.headers.get("x-real-ip") or (request.client.host if request.client else "?")  # set by the proxy; the app is not published
    now = time.time()
    recent = [t for t in _ip_fails.get(ip, []) if now - t < 600]
    if len(recent) >= 50:
        return JSONResponse({"error": "Too many failed sign-ins from this address. Wait ten minutes."}, status_code=429)
    name, password = str(body.get("username", "")), str(body.get("password", ""))
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT id, username, pw_hash, role, disabled, must_change, failed_attempts, locked_until, locked_until > NOW() FROM users WHERE username=%s FOR UPDATE", (name,))
        row = cur.fetchone()
        if row and row[8]:
            cur.execute("SELECT CEIL(TIMESTAMPDIFF(SECOND, NOW(), locked_until)/60) FROM users WHERE id=%s", (row[0],))
            mins = int(cur.fetchone()[0] or 1)
            return JSONResponse({"error": f"Too many wrong passwords. Try again in {mins} minute{'s' if mins != 1 else ''}."}, status_code=429)
        ok = check_password(row[2] if row else _DUMMY_HASH, password) and row is not None and not row[4]
        if not ok:
            _ip_fails[ip] = recent + [now]
            if row:
                fails = row[6] + 1
                if fails >= LOCK_AFTER:
                    cur.execute("UPDATE users SET failed_attempts=0, locked_until=NOW() + INTERVAL %s MINUTE WHERE id=%s", (int(LOCK_FOR.total_seconds() // 60), row[0]))
                    audit(cur, row[1], "locked", f"{LOCK_AFTER} wrong passwords from {ip}")
                else:
                    cur.execute("UPDATE users SET failed_attempts=%s WHERE id=%s", (fails, row[0]))
                    audit(cur, row[1], "login-failed", ip)
            c.commit()
            return JSONResponse({"error": "Wrong user name or password"}, status_code=401)
        cur.execute("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=NOW() WHERE id=%s", (row[0],))
        set_session(response, request, row[0], cur)
        audit(cur, row[1], "login", ip)
    return {"user": row[1], "role": row[3], "mustChange": bool(row[5])}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    u = request.state.user
    with conn_ctx() as c, c.cursor() as cur:
        if u.get("token"):
            cur.execute("DELETE FROM sessions WHERE token_hash=%s", (u["token"],))
            audit(cur, u["name"], "logout")
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.post("/api/me/password")
def change_my_password(request: Request, body: dict = Body(...)):
    u = request.state.user
    if u["open"]:
        raise HTTPException(400, "Create a user first")
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT pw_hash FROM users WHERE id=%s", (u["id"],))
        if not check_password(cur.fetchone()[0], str(body.get("current", ""))):
            raise HTTPException(400, "The current password is wrong")
        new = str(body.get("new", ""))
        if new == str(body.get("current", "")):
            raise HTTPException(400, "Choose a password different from the current one")
        validate_new_password(u["name"], new)
        cur.execute("UPDATE users SET pw_hash=%s, must_change=0 WHERE id=%s", (hash_password(new), u["id"]))
        cur.execute("DELETE FROM sessions WHERE user_id=%s AND token_hash<>%s", (u["id"], u["token"]))
        audit(cur, u["name"], "password-changed")
    return {"ok": True}


# ------------------------------------------------------------------ user management (admin)

@app.get("/api/users")
def list_users():
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT username, role, disabled, must_change, locked_until IS NOT NULL AND locked_until > NOW(), created_at, last_login FROM users ORDER BY username")
        return [{"username": a, "role": b, "disabled": bool(d), "mustChange": bool(m), "locked": bool(l),
                 "createdAt": ca.isoformat() if ca else None, "lastLogin": ll.isoformat() if ll else None} for a, b, d, m, l, ca, ll in cur.fetchall()]


@app.post("/api/users")
def add_user(request: Request, response: Response, body: dict = Body(...)):
    u = request.state.user
    name, role = str(body.get("username", "")).strip(), body.get("role", "editor")
    with conn_ctx() as c, c.cursor() as cur:
        first = u["open"]
        uid = create_user(cur, name, str(body.get("password", "")), "admin" if first else role, bool(body.get("mustChange")) and not first)
        audit(cur, u["name"], "user-added", f"{name} as {'admin' if first else role}")
        if first:  # the person who set up the first administrator is signed straight in as them
            set_session(response, request, uid, cur)
    return {"ok": True, "firstUser": first}


@app.patch("/api/users/{username}")
def edit_user(username: str, request: Request, body: dict = Body(...)):
    u = request.state.user
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT id, role, disabled FROM users WHERE username=%s FOR UPDATE", (username,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "No such user")
        uid, role, disabled = row
        me = u.get("id") == uid
        notes = []
        if "role" in body and body["role"] != role:
            if body["role"] not in RANK:
                raise HTTPException(400, "Role must be viewer, editor or admin")
            if me:
                raise HTTPException(400, "You cannot change your own role")
            if role == "admin" and active_admins(cur, username) == 0:
                raise HTTPException(400, "That would leave no administrator")
            cur.execute("UPDATE users SET role=%s WHERE id=%s", (body["role"], uid)); notes.append(f"role {role} -> {body['role']}")
            cur.execute("DELETE FROM sessions WHERE user_id=%s", (uid,))
        if "disabled" in body and bool(body["disabled"]) != bool(disabled):
            if body["disabled"]:
                if me:
                    raise HTTPException(400, "You cannot disable yourself")
                if role == "admin" and active_admins(cur, username) == 0:
                    raise HTTPException(400, "That would leave no administrator")
                cur.execute("DELETE FROM sessions WHERE user_id=%s", (uid,))
            cur.execute("UPDATE users SET disabled=%s WHERE id=%s", (1 if body["disabled"] else 0, uid)); notes.append("disabled" if body["disabled"] else "enabled")
        if body.get("password"):
            validate_new_password(username, str(body["password"]))
            cur.execute("UPDATE users SET pw_hash=%s, must_change=%s, failed_attempts=0, locked_until=NULL WHERE id=%s",
                        (hash_password(str(body["password"])), 0 if body.get("mustChange") is False else 1, uid))
            if not me:
                cur.execute("DELETE FROM sessions WHERE user_id=%s", (uid,))
            notes.append("password reset")
        if body.get("unlock"):
            cur.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=%s", (uid,)); notes.append("unlocked")
        if notes:
            audit(cur, u["name"], "user-edited", f"{username}: {', '.join(notes)}")
    return {"ok": True}


@app.delete("/api/users/{username}")
def delete_user(username: str, request: Request):
    u = request.state.user
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT id, role FROM users WHERE username=%s FOR UPDATE", (username,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "No such user")
        if u.get("id") == row[0]:
            raise HTTPException(400, "You cannot delete yourself")
        if row[1] == "admin" and active_admins(cur, username) == 0:
            raise HTTPException(400, "That would leave no administrator")
        cur.execute("DELETE FROM users WHERE id=%s", (row[0],))
        audit(cur, u["name"], "user-deleted", username)
    return {"ok": True}


# ------------------------------------------------------------------ collections

def check_name(name):
    if name not in COLLECTIONS:
        raise HTTPException(404, "Unknown collection")


@app.get("/api/state")
def state():
    """Every collection in one call, so the page can start with its data in memory."""
    out = {}
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT name, kind, revision FROM collections")
        meta = {n: (k, r) for n, k, r in cur.fetchall()}
        cur.execute("SELECT collection, doc FROM records ORDER BY collection, seq")
        docs = {}
        for coll, doc in cur.fetchall():
            docs.setdefault(coll, []).append(doc)
    parts = []
    for name, (kind, rev) in meta.items():
        d = docs.get(name, [])
        body = d[0] if kind == "object" and d else ("{}" if kind == "object" else "[" + ",".join(d) + "]")
        parts.append(f'{json.dumps(name)}:{{"revision":{rev},"data":{body}}}')
    return Response("{" + ",".join(parts) + "}", media_type="application/json", headers={"Cache-Control": "no-store"})


def short(v, n=160):
    t = v if isinstance(v, str) else json.dumps(v, separators=(",", ":"), ensure_ascii=False)
    return t if len(t) <= n else t[:n] + "…"


def log_changes(cur, user, name, old_docs, new_data):
    """Write who changed which record (register and risk acceptances only) to the change history."""
    keyf, labelf = TRACKED[name]
    old = {}
    for d in old_docs:
        o = json.loads(d)
        old[str(o.get(keyf))] = o
    new = {str(o.get(keyf)): o for o in new_data if isinstance(o, dict)}
    rows = []
    for k, n in new.items():
        o = old.get(k)
        if o is None:
            rows.append((str(n.get(labelf, k)), "add", None))
        elif o != n:
            ch = {f: {"from": short(o.get(f)), "to": short(n.get(f))} for f in sorted(set(o) | set(n)) if o.get(f) != n.get(f)}
            rows.append((str(n.get(labelf, k)), "change", json.dumps(ch, ensure_ascii=False)[:8000]))
    for k, o in old.items():
        if k not in new:
            rows.append((str(o.get(labelf, k)), "remove", None))
    if not rows:
        return
    if len(rows) > 500:  # an import or restore: one summary line instead of hundreds
        counts = {a: sum(1 for r in rows if r[1] == a) for a in ("add", "change", "remove")}
        cur.execute("INSERT INTO change_log (at, user, collection, record_key, action, changes) VALUES (NOW(3),%s,%s,%s,'bulk',%s)",
                    (user, name, f"{len(rows)} records", json.dumps(counts)))
        return
    cur.executemany("INSERT INTO change_log (at, user, collection, record_key, action, changes) VALUES (NOW(3),%s,%s,%s,%s,%s)",
                    [(user, name, key[:255], act, ch) for key, act, ch in rows])


@app.put("/api/collections/{name}")
def put_collection(name: str, request: Request, body: dict = Body(...)):
    check_name(name)
    if name in PER_RECORD:
        raise HTTPException(400, "Remediation tasks are saved one at a time (api/tasks)")
    data = body.get("data")
    base = body.get("baseRevision")  # None = overwrite whatever is there
    if isinstance(data, list):
        kind, docs = "array", [json.dumps(x, separators=(",", ":")) for x in data]
    elif isinstance(data, dict):
        kind, docs = "object", [json.dumps(data, separators=(",", ":"))]
    else:
        raise HTTPException(400, "data must be an array or an object")
    user = current_user(request)
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT revision FROM collections WHERE name=%s FOR UPDATE", (name,))
        row = cur.fetchone()
        rev = row[0] if row else 0
        if base is not None and base != rev:
            c.rollback()
            return JSONResponse({"conflict": True, "revision": rev}, status_code=409)
        if name == "gov_status_settings":
            # The status rules are an administrator's job. An editor's page may only set the go-live date once, while it is empty.
            u = getattr(request.state, "user", None) or {}
            if u.get("role") != "admin" and not u.get("open"):
                cur.execute("SELECT doc FROM records WHERE collection=%s LIMIT 1", (name,))
                r = cur.fetchone()
                old = json.loads(r[0]) if r else {}
                if old.get("goLive") or not isinstance(data, dict) or any(k != "goLive" and data.get(k) != old.get(k) for k in set(data) | set(old)):
                    c.rollback()
                    return JSONResponse({"error": "Only an administrator can change the status rules"}, status_code=403)
        if name == "gov_org_settings":
            # The organisation setup (teams, name matching, rules) is an administrator's job (v3.20).
            u = getattr(request.state, "user", None) or {}
            if u.get("role") != "admin" and not u.get("open"):
                c.rollback()
                return JSONResponse({"error": "Only an administrator can change the organisation setup"}, status_code=403)
        if name in TRACKED and kind == "array":
            cur.execute("SELECT doc FROM records WHERE collection=%s", (name,))
            log_changes(cur, user, name, [r[0] for r in cur.fetchall()], data)
        cur.execute("DELETE FROM records WHERE collection=%s", (name,))
        for i in range(0, len(docs), 500):
            chunk = docs[i:i + 500]
            cur.executemany("INSERT INTO records (collection, seq, doc) VALUES (%s,%s,%s)", [(name, i + j, d) for j, d in enumerate(chunk)])
        rev += 1
        cur.execute(
            "INSERT INTO collections (name, kind, revision, updated_at, updated_by) VALUES (%s,%s,%s,NOW(3),%s) "
            "ON DUPLICATE KEY UPDATE kind=VALUES(kind), revision=VALUES(revision), updated_at=VALUES(updated_at), updated_by=VALUES(updated_by)",
            (name, kind, rev, user))
        audit(cur, user, "save", f"{name} ({len(docs)} records, rev {rev})")
    return {"revision": rev}


@app.delete("/api/collections/{name}")
def delete_collection(name: str, request: Request):
    check_name(name)
    user = current_user(request)
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("DELETE FROM records WHERE collection=%s", (name,))
        cur.execute("DELETE FROM collections WHERE name=%s", (name,))
        audit(cur, user, "delete", name)
    return {"ok": True}


# ------------------------------------------------------------------ remediation tasks

TASKS = "gov_remediation"
TASK_STATUSES = {"Open", "Planned", "In progress", "Fixed, awaiting scan", "Verified", "Risk accepted", "Cancelled"}
CLOSED_STATUSES = {"Verified", "Cancelled", "Risk accepted"}
ASSET_STATES = {"open", "fixed", "verified", "excluded", "moved"}
TASK_TYPES = {"vuln", "eol", "other"}


def _txt(v, n):
    return str(v if v is not None else "")[:n]


def _date(v):
    v = _txt(v, 10)
    try:
        datetime.strptime(v, "%Y-%m-%d")
        return v
    except ValueError:
        return ""


def enabled_users(cur):
    cur.execute("SELECT username FROM users WHERE disabled=0")
    return {r[0] for r in cur.fetchall()}


def clean_task(t, cur):
    """Only known fields, sane sizes and values. The server owns id, rev, who/when and the comment log."""
    if not isinstance(t, dict):
        raise HTTPException(400, "task must be an object")
    title = _txt(t.get("title"), 300).strip()
    if not title:
        raise HTTPException(400, "A task needs a title")
    status = t.get("status") or "Open"
    if status not in TASK_STATUSES:
        raise HTTPException(400, "Unknown status")
    typ = t.get("type") or "other"
    if typ not in TASK_TYPES:
        raise HTTPException(400, "Unknown task type")
    assignee = _txt(t.get("assignee"), 60)
    if assignee and assignee not in enabled_users(cur):
        raise HTTPException(400, f"No enabled portal user called {assignee}")
    assets = []
    for a in (t.get("assets") or [])[:5000]:
        if not isinstance(a, dict) or not a.get("name"):
            continue
        st = a.get("state") or "open"
        if st not in ASSET_STATES:
            raise HTTPException(400, "Unknown asset state")
        chk = a.get("chk") if isinstance(a.get("chk"), dict) else {}
        ok = a.get("ok") if isinstance(a.get("ok"), dict) else {}
        assets.append({"name": _txt(a["name"], 255), "state": st, "at": _txt(a.get("at"), 40), "by": _txt(a.get("by"), 60),
                       "note": _txt(a.get("note"), 300), "movedTo": _txt(a.get("movedTo"), 20),
                       # what a scan or asset import must show for this asset to count as fixed, and the last results
                       "chk": {k: v for k, v in {"os": _txt(chk.get("os"), 200), "hw": _txt(chk.get("hw"), 200),
                                                  "qids": [_txt(q, 20) for q in (chk.get("qids") or [])[:200]]}.items() if v},
                       "ok": {k: bool(v) for k, v in ok.items() if k in ("os", "hw", "qids")}})
    src = t.get("source") if isinstance(t.get("source"), dict) else {}
    source = {"kind": _txt(src.get("kind"), 20), "key": _txt(src.get("key"), 300), "label": _txt(src.get("label"), 300),
              "qids": [_txt(q, 20) for q in (src.get("qids") or [])[:500]], "match": _txt(src.get("match"), 300)}
    return {"type": typ, "title": title, "source": source, "assets": assets, "team": _txt(t.get("team"), 40),
            "assignee": assignee, "priority": _txt(t.get("priority"), 40), "priorityRank": int(t.get("priorityRank") or 9),
            "due": _date(t.get("due")), "status": status, "ticket": _txt(t.get("ticket"), 120), "splitFrom": _txt(t.get("splitFrom"), 20),
            "reopened": bool(t.get("reopened")), "lastCheck": _txt(t.get("lastCheck"), 300)}


def lock_tasks(cur, user):
    """Lock the task collection (creating its row on first use, or /api/state would not return it).
    Lock first and insert only when missing: an INSERT IGNORE on every call deadlocks under parallel saves."""
    cur.execute("SELECT revision FROM collections WHERE name=%s FOR UPDATE", (TASKS,))
    if cur.fetchone() is None:
        try:
            cur.execute("INSERT INTO collections (name, kind, revision, updated_at, updated_by) VALUES (%s,'array',0,NOW(3),%s)", (TASKS, user))
        except pymysql.err.IntegrityError:
            pass                                    # someone else created it a moment ago
        cur.execute("SELECT revision FROM collections WHERE name=%s FOR UPDATE", (TASKS,))
    cur.execute("SELECT seq, doc FROM records WHERE collection=%s ORDER BY seq", (TASKS,))
    return [(seq, json.loads(doc)) for seq, doc in cur.fetchall()]


def retry_deadlock(fn, tries=4):
    """Run a write transaction again if MariaDB picked it as a deadlock victim (rare, under parallel saves)."""
    for i in range(tries):
        try:
            return fn()
        except pymysql.err.OperationalError as e:
            if e.args and e.args[0] in (1213, 1205) and i < tries - 1:
                time.sleep(0.05 * (i + 1))
                continue
            raise


def bump_tasks(cur, user):
    cur.execute("UPDATE collections SET revision=revision+1, updated_at=NOW(3), updated_by=%s WHERE name=%s", (user, TASKS))


def for_log(t):
    """A task without the fields that change on every save, so the history shows only real changes;
    assets as a short count by state instead of the whole list."""
    out = {k: v for k, v in t.items() if k not in ("rev", "updatedAt", "updatedBy", "comments", "assets")}
    counts = {}
    for a in t.get("assets") or []:
        counts[a.get("state", "open")] = counts.get(a.get("state", "open"), 0) + 1
    out["assets"] = " · ".join(f"{k} {counts[k]}" for k in ("open", "fixed", "verified", "excluded", "moved") if counts.get(k)) or "none"
    return out


def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@app.get("/api/people")
def people():
    """Enabled user names, for choosing who a task is assigned to (any signed-in role may read this)."""
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT username, role FROM users WHERE disabled=0 ORDER BY username")
        return [{"username": a, "role": b} for a, b in cur.fetchall()]


@app.get("/api/tasks")
def list_tasks():
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT doc FROM records WHERE collection=%s ORDER BY seq", (TASKS,))
        body = "[" + ",".join(r[0] for r in cur.fetchall()) + "]"
    return Response(body, media_type="application/json", headers={"Cache-Control": "no-store"})


@app.post("/api/tasks")
def create_tasks(request: Request, body: dict = Body(...)):
    """Create one or more tasks in one go (one per team, or a split). Returns them with their new ids."""
    user = current_user(request)
    items = body.get("tasks") if isinstance(body.get("tasks"), list) else [body.get("task")]
    if not items or len(items) > 50:
        raise HTTPException(400, "Send 1 to 50 tasks")
    return retry_deadlock(lambda: _create_tasks(user, items))


def _create_tasks(user, items):
    out = []
    with conn_ctx() as c, c.cursor() as cur:
        rows = lock_tasks(cur, user)
        nums = [int(d["id"].split("-")[1]) for _, d in rows if str(d.get("id", "")).startswith("TASK-") and str(d["id"].split("-")[1]).isdigit()]
        n = max(nums, default=0)
        seq = max((s for s, _ in rows), default=-1)
        when = now_iso()
        for raw in items:
            t = clean_task(raw, cur)
            n += 1
            seq += 1
            first = _txt((raw or {}).get("comment"), 4000).strip()
            t.update({"id": f"TASK-{n:04d}", "rev": 1, "createdAt": when, "createdBy": user, "updatedAt": when, "updatedBy": user,
                      "closedAt": when if t["status"] in CLOSED_STATUSES else "",
                      "comments": [{"at": when, "by": user, "text": first}] if first else []})
            cur.execute("INSERT INTO records (collection, seq, doc) VALUES (%s,%s,%s)", (TASKS, seq, json.dumps(t, separators=(",", ":"))))
            log_changes(cur, user, TASKS, [], [for_log(t)])
            out.append(t)
        bump_tasks(cur, user)
        audit(cur, user, "task-created", ", ".join(t["id"] for t in out))
    return {"tasks": out}


@app.put("/api/tasks/{task_id}")
def update_task(task_id: str, request: Request, body: dict = Body(...)):
    """Save one task. baseRev must be the revision the page last saw, otherwise 409 with the current copy."""
    user = current_user(request)
    return retry_deadlock(lambda: _update_task(user, task_id, body))


def _update_task(user, task_id, body):
    with conn_ctx() as c, c.cursor() as cur:
        rows = lock_tasks(cur, user)
        hit = next(((s, d) for s, d in rows if d.get("id") == task_id), None)
        if not hit:
            raise HTTPException(404, "No such task")
        seq, old = hit
        if body.get("baseRev") != old.get("rev"):
            c.rollback()
            return JSONResponse({"conflict": True, "task": old}, status_code=409)
        t = clean_task(body.get("task"), cur)
        when = now_iso()
        t.update({"id": task_id, "rev": old.get("rev", 0) + 1, "createdAt": old.get("createdAt"), "createdBy": old.get("createdBy"),
                  "updatedAt": when, "updatedBy": user, "comments": old.get("comments", []),
                  "closedAt": (old.get("closedAt") or when) if t["status"] in CLOSED_STATUSES else ""})
        text = _txt(body.get("comment"), 4000).strip()
        if text:
            t["comments"] = t["comments"] + [{"at": when, "by": user, "text": text}]
        cur.execute("UPDATE records SET doc=%s WHERE collection=%s AND seq=%s", (json.dumps(t, separators=(",", ":")), TASKS, seq))
        log_changes(cur, user, TASKS, [json.dumps(for_log(old))], [for_log(t)])
        bump_tasks(cur, user)
    return {"task": t}


@app.post("/api/tasks/{task_id}/comments")
def add_comment(task_id: str, request: Request, body: dict = Body(...)):
    """Add a comment without needing the latest revision (two people commenting never clash)."""
    user = current_user(request)
    text = _txt(body.get("text"), 4000).strip()
    if not text:
        raise HTTPException(400, "Empty comment")
    return retry_deadlock(lambda: _add_comment(user, task_id, text))


def _add_comment(user, task_id, text):
    with conn_ctx() as c, c.cursor() as cur:
        rows = lock_tasks(cur, user)
        hit = next(((s, d) for s, d in rows if d.get("id") == task_id), None)
        if not hit:
            raise HTTPException(404, "No such task")
        seq, t = hit
        when = now_iso()
        t["comments"] = (t.get("comments") or []) + [{"at": when, "by": user, "text": text}]
        t.update({"rev": t.get("rev", 0) + 1, "updatedAt": when, "updatedBy": user})
        cur.execute("UPDATE records SET doc=%s WHERE collection=%s AND seq=%s", (json.dumps(t, separators=(",", ":")), TASKS, seq))
        bump_tasks(cur, user)
    return {"task": t}


# ------------------------------------------------------------------ End-of-life dates (endoflife.date, fetched by the server, v4.12)

@app.get("/api/eol/status")
def eol_status():
    return eol.status()


@app.post("/api/eol/sync")
def eol_sync(request: Request):
    """Fetch the dates again now (editors)."""
    if not eol.start(current_user(request)):
        return JSONResponse({"error": "Already fetching", "job": eol.status()["job"]}, status_code=409)
    return JSONResponse({"started": True}, status_code=202)


@app.get("/api/redhat/status")
def redhat_status():
    """Data Health: when the watched CVEs were last refreshed from Red Hat, how many CVEs are kept."""
    return redhat.status()


@app.post("/api/redhat/sync")
def redhat_sync(request: Request):
    if not redhat.start(current_user(request)):
        return JSONResponse({"error": "A refresh is already running"}, status_code=409)
    return JSONResponse({"started": True}, status_code=202)


@app.get("/api/redhat")
async def redhat_cves(ids: str = ""):
    """v4.22 Red Hat Security Data for up to 20 CVEs (cached a day on the server; only CVE numbers leave it)."""
    return await run_in_threadpool(redhat.get, ids.split(","))


@app.get("/api/eol/data")
def eol_data():
    return Response(eol.data_json(), media_type="application/json", headers={"Cache-Control": "no-store"})


# ------------------------------------------------------------------ Automox (read-only patch data)

@app.get("/api/automox/status")
def automox_status():
    """Whether Automox is set up, the running sync and the last result. Never the key."""
    return automox.status()


@app.post("/api/automox/sync")
def automox_sync(request: Request, body: dict = Body(default={})):
    """Start a sync (editors). deviceIds: Automox devices to check for installed fixes (assets with open tasks)."""
    ids = body.get("deviceIds") if isinstance(body.get("deviceIds"), list) else []
    try:
        started = automox.start(current_user(request), ids[:5000])
    except automox.AxError as e:
        return JSONResponse({"error": str(e), "kind": e.kind}, status_code=400)
    if not started:
        return JSONResponse({"error": "A sync is already running", "job": automox.status()["job"]}, status_code=409)
    return JSONResponse({"started": True}, status_code=202)


@app.get("/api/automox/data")
def automox_data():
    return Response(automox.data_json(), media_type="application/json", headers={"Cache-Control": "no-store"})


# ------------------------------------------------------------------ Qualys API (read-only sync of findings)

@app.get("/api/qualys/status")
def qualys_status():
    """Whether the Qualys sync is set up, the running sync, the last result and who applied it. Never the login."""
    return qualys.status()


@app.post("/api/qualys/sync")
def qualys_sync(request: Request):
    try:
        started = qualys.start(current_user(request))
    except qualys.QxError as e:
        return JSONResponse({"error": str(e), "kind": e.kind}, status_code=400)
    if not started:
        return JSONResponse({"error": "A sync is already running", "job": qualys.status()["job"]}, status_code=409)
    return JSONResponse({"started": True}, status_code=202)


@app.post("/api/qualys/cve")
async def qualys_cve(request: Request):
    """v4.18 Refresh this CVE: the findings for one CVE's QIDs on every host, straight from Qualys (read-only)."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    try:
        res = await run_in_threadpool(qualys.cve_refresh, body.get("cves") or [], body.get("qids") or [])
    except qualys.QxError as e:
        return JSONResponse({"error": str(e), "kind": e.kind}, status_code=409 if e.kind == "busy" else 400)
    try:
        with conn_ctx() as c, c.cursor() as cur:
            audit(cur, current_user(request), "qualys-cve-refresh", f"{', '.join(res['cves'])}: {len(res['hosts'])} hosts")
    except Exception:
        pass
    return res


@app.get("/api/qualys/history")
def qualys_history():
    """The last syncs (successes and failures): steps, counts, changes, who applied them."""
    return qualys.history()


@app.get("/api/qualys/data")
def qualys_data():
    return StreamingResponse(qualys.data_stream(), media_type="application/json", headers={"Cache-Control": "no-store"})


@app.post("/api/qualys/claim")
def qualys_claim(request: Request, body: dict = Body(...)):
    """An editor's page asks to apply the latest sync; only one page gets it."""
    ok, why = qualys.claim(current_user(request), str(body.get("syncId") or ""), str(body.get("page") or "")[:64])
    return {"ok": True} if ok else JSONResponse({"error": why}, status_code=409)


@app.post("/api/qualys/applied")
def qualys_applied(request: Request, body: dict = Body(...)):
    s = body.get("summary") if isinstance(body.get("summary"), dict) else {}
    ok = qualys.applied(current_user(request), str(body.get("syncId") or ""), {k: s[k] for k in list(s)[:20]})
    return {"ok": True} if ok else JSONResponse({"error": "No claim for that sync"}, status_code=409)


# ------------------------------------------------------------------ vulnerabilities

def stream_table(sql):
    def gen():
        c = connect(cursorclass=pymysql.cursors.SSCursor)
        try:
            with c.cursor() as cur:
                cur.execute(sql)
                # Send in blocks of about 1 MB: one yield per row made 180,000 tiny chunks and took ~50 s.
                buf, size, first = ["["], 1, True
                for (doc,) in cur:
                    piece = doc if first else "," + doc
                    first = False
                    buf.append(piece)
                    size += len(piece)
                    if size >= 1_000_000:
                        yield "".join(buf)
                        buf, size = [], 0
                buf.append("]")
                yield "".join(buf)
        finally:
            c.close()
    return StreamingResponse(gen(), media_type="application/json", headers={"Cache-Control": "no-store"})


@app.get("/api/vuln/detections")
def get_detections():
    return stream_table("SELECT doc FROM detections")


@app.get("/api/vuln/qids")
def get_qids():
    return stream_table("SELECT doc FROM qids")


@app.post("/api/vuln/merge")
def vuln_merge(request: Request, body: dict = Body(...)):
    """Replace the detections of `assets` (or everything with clearAll), then upsert the given rows.
    The page sends big imports as several calls: the first carries assets/clearAll, the rest only rows."""
    dets = body.get("detections") or []
    qids = body.get("qids") or []
    assets = body.get("assets") or []
    clear = bool(body.get("clearAll"))
    user = current_user(request)
    with conn_ctx() as c, c.cursor() as cur:
        if clear:
            cur.execute("DELETE FROM detections")
            cur.execute("DELETE FROM qids")
        else:
            for i in range(0, len(assets), 500):
                chunk = assets[i:i + 500]
                cur.execute("DELETE FROM detections WHERE asset IN (%s)" % ",".join(["%s"] * len(chunk)), chunk)
        if dets:
            cur.executemany(
                "INSERT INTO detections (k, asset, qid, sev, qvs, doc) VALUES (%s,%s,%s,%s,%s,%s) "
                "ON DUPLICATE KEY UPDATE asset=VALUES(asset), qid=VALUES(qid), sev=VALUES(sev), qvs=VALUES(qvs), doc=VALUES(doc)",
                [(d["k"], d["asset"], str(d["qid"]), int(d.get("sev") or 0), float(d.get("qvs") or 0), json.dumps(d, separators=(",", ":"))) for d in dets])
        if qids:
            cur.executemany(
                "INSERT INTO qids (qid, doc) VALUES (%s,%s) ON DUPLICATE KEY UPDATE doc=VALUES(doc)",
                [(str(q["qid"]), json.dumps(q, separators=(",", ":"))) for q in qids])
        if clear or assets or dets:
            audit(cur, user, "vuln-merge", f"{'clear all, ' if clear else ''}{len(assets)} assets replaced, {len(dets)} detections, {len(qids)} qids")
    return {"ok": True}


@app.delete("/api/vuln")
def vuln_clear(request: Request):
    user = current_user(request)
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("DELETE FROM detections")
        cur.execute("DELETE FROM qids")
        audit(cur, user, "vuln-clear")
    return {"ok": True}


@app.post("/api/restore")
def restore(request: Request, body: dict = Body(...)):
    """Replace ALL data with the contents of a backup file made by the page, in one transaction."""
    user = current_user(request)
    vs = body.get("vulnStore") or {}
    dets, qids = vs.get("detections") or [], vs.get("qids") or []
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT name, revision FROM collections FOR UPDATE")
        revs = dict(cur.fetchall())
        cur.execute("DELETE FROM records")
        cur.execute("DELETE FROM collections")
        cur.execute("DELETE FROM detections")
        cur.execute("DELETE FROM qids")
        kept = 0
        for field, name in FIELD_MAP.items():
            data = body.get(field)
            if data is None:
                continue
            kind, docs = ("array", [json.dumps(x, separators=(",", ":")) for x in data]) if isinstance(data, list) else ("object", [json.dumps(data, separators=(",", ":"))])
            for i in range(0, len(docs), 500):
                cur.executemany("INSERT INTO records (collection, seq, doc) VALUES (%s,%s,%s)", [(name, i + j, d) for j, d in enumerate(docs[i:i + 500])])
            # revisions only go up, so any page still open with the old data is told to reload on its next save
            cur.execute("INSERT INTO collections (name, kind, revision, updated_at, updated_by) VALUES (%s,%s,%s,NOW(3),%s)", (name, kind, revs.get(name, 0) + 1, user))
            kept += 1
        for i in range(0, len(dets), 2000):
            cur.executemany("INSERT INTO detections (k, asset, qid, sev, qvs, doc) VALUES (%s,%s,%s,%s,%s,%s)",
                            [(d["k"], d["asset"], str(d["qid"]), int(d.get("sev") or 0), float(d.get("qvs") or 0), json.dumps(d, separators=(",", ":"))) for d in dets[i:i + 2000]])
        if qids:
            cur.executemany("INSERT INTO qids (qid, doc) VALUES (%s,%s)", [(str(q["qid"]), json.dumps(q, separators=(",", ":"))) for q in qids])
        audit(cur, user, "restore", f"{kept} collections, {len(dets)} detections, {len(qids)} qids")
    return {"ok": True}


@app.get("/api/history")
def history(record: str = "", user: str = "", collection: str = "", limit: int = 200):
    """Who changed which register / risk-acceptance record, newest first."""
    q, args = "SELECT at, user, collection, record_key, action, changes FROM change_log WHERE 1=1", []
    if record:
        q += " AND record_key LIKE %s"; args.append("%" + record.replace("%", "") + "%")
    if user:
        q += " AND user=%s"; args.append(user)
    if collection:
        q += " AND collection=%s"; args.append(collection)
    q += " ORDER BY id DESC LIMIT %s"; args.append(min(max(limit, 1), 1000))
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute(q, args)
        return [{"at": a.isoformat(), "user": u, "collection": co, "record": r, "action": ac, "changes": json.loads(ch) if ch else None}
                for a, u, co, r, ac, ch in cur.fetchall()]


@app.get("/api/audit")
def get_audit(limit: int = 200):
    """Activity: sign-ins, user changes, imports, restores (administrators only)."""
    with conn_ctx() as c, c.cursor() as cur:
        cur.execute("SELECT at, user, action, detail FROM audit_log ORDER BY id DESC LIMIT %s", (min(max(limit, 1), 1000),))
        return [{"at": a.isoformat(), "user": u, "action": ac, "detail": d} for a, u, ac, d in cur.fetchall()]
