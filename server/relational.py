"""Stage 1 of the database work: proper tables beside the old storage (v4.42).

Until now everything lived as JSON documents: the `records` table (one row per document, grouped by collection),
plus `detections` and `qids` with a few columns and the rest as JSON. The page downloads all of it and works it out
in the browser, which gets slower as the data grows.

This module adds relational tables for the data the reports filter, join and count on:

    assets              one row per machine in the register (gov_asset_register)
    findings            one row per open/fixed finding (from detections), keyed like it
    vulns, vuln_cves    the QID catalogue and the CVEs of each QID
    risk_acceptances, risk_acceptance_qids
    tasks, task_assets, task_qids      remediation tasks (gov_remediation)
    notes               comments on machines and findings (gov_asset_notes)
    review_queue        machines waiting for a team (gov_review_queue)
    schema_meta         what was built, when, and what the last check found

Each main row has typed, indexed columns for the fields queries need AND the full original document (`doc`), so the
old API can later be answered from these tables byte for byte (stage 2) while new queries use the columns (stage 3).

STAGE 1 RULES: the app does not read or write these tables yet. They are rebuilt from the old storage (in one
consistent read) when the server starts and when an administrator asks, and `verify()` proves nothing was lost:
every document comes back identical, and every column agrees with its document. The old tables are never changed,
so rolling back is simply running the previous version.
"""
import json
import time

SCHEMA_VERSION = 1

TABLES = [
    """CREATE TABLE IF NOT EXISTS schema_meta (
        k VARCHAR(60) NOT NULL PRIMARY KEY,
        v LONGTEXT NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS assets (
        name VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL PRIMARY KEY,
        seq INT NOT NULL,
        original_name VARCHAR(255) NOT NULL DEFAULT '',
        owner VARCHAR(100) NOT NULL DEFAULT '',
        service VARCHAR(120) NOT NULL DEFAULT '',
        status VARCHAR(30) NOT NULL DEFAULT '',
        environment VARCHAR(30) NOT NULL DEFAULT '',
        exposure VARCHAR(30) NOT NULL DEFAULT '',
        tier TINYINT NULL,
        ha CHAR(1) NOT NULL DEFAULT '',
        os VARCHAR(255) NOT NULL DEFAULT '',
        os_lifecycle VARCHAR(40) NOT NULL DEFAULT '',
        ipv4 VARCHAR(100) NOT NULL DEFAULT '',
        last_seen VARCHAR(40) NOT NULL DEFAULT '',
        risk_status VARCHAR(30) NOT NULL DEFAULT '',
        unrecognised TINYINT(1) NOT NULL DEFAULT 0,
        patch_na TINYINT(1) NOT NULL DEFAULT 0,
        doc LONGTEXT NOT NULL,
        KEY idx_owner (owner), KEY idx_service (service), KEY idx_status (status), KEY idx_seq (seq)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS vulns (
        qid VARCHAR(20) NOT NULL PRIMARY KEY,
        title VARCHAR(500) NOT NULL DEFAULT '',
        category VARCHAR(100) NOT NULL DEFAULT '',
        sev TINYINT NOT NULL DEFAULT 0,
        cvss FLOAT NOT NULL DEFAULT 0,
        patchable TINYINT(1) NOT NULL DEFAULT 0,
        published VARCHAR(40) NOT NULL DEFAULT '',
        patch_released VARCHAR(60) NOT NULL DEFAULT '',
        doc LONGTEXT NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS vuln_cves (
        qid VARCHAR(20) NOT NULL,
        cve VARCHAR(40) NOT NULL,
        cvss FLOAT NOT NULL DEFAULT 0,
        PRIMARY KEY (qid, cve), KEY idx_cve (cve)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS findings (
        k VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL PRIMARY KEY,
        asset VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
        qid VARCHAR(20) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT '',
        sev TINYINT NOT NULL DEFAULT 0,
        qvs FLOAT NOT NULL DEFAULT 0,
        cvss FLOAT NOT NULL DEFAULT 0,
        port VARCHAR(20) NOT NULL DEFAULT '',
        first_found VARCHAR(40) NOT NULL DEFAULT '',
        last_found VARCHAR(40) NOT NULL DEFAULT '',
        patchable TINYINT(1) NOT NULL DEFAULT 0,
        doc LONGTEXT NOT NULL,
        KEY idx_asset (asset), KEY idx_qid (qid), KEY idx_status (status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS risk_acceptances (
        id VARCHAR(80) NOT NULL PRIMARY KEY,
        seq INT NOT NULL,
        asset VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '',
        scope VARCHAR(20) NOT NULL DEFAULT '',
        status VARCHAR(30) NOT NULL DEFAULT '',
        acc_date VARCHAR(40) NOT NULL DEFAULT '',
        rev_date VARCHAR(40) NOT NULL DEFAULT '',
        exp_date VARCHAR(40) NOT NULL DEFAULT '',
        doc LONGTEXT NOT NULL,
        KEY idx_asset (asset), KEY idx_seq (seq)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS risk_acceptance_qids (
        ra_id VARCHAR(80) NOT NULL,
        qid VARCHAR(20) NOT NULL,
        PRIMARY KEY (ra_id, qid), KEY idx_qid (qid)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS tasks (
        id VARCHAR(40) NOT NULL PRIMARY KEY,
        seq INT NOT NULL,
        type VARCHAR(20) NOT NULL DEFAULT '',
        status VARCHAR(40) NOT NULL DEFAULT '',
        team VARCHAR(100) NOT NULL DEFAULT '',
        assignee VARCHAR(100) NOT NULL DEFAULT '',
        due VARCHAR(40) NOT NULL DEFAULT '',
        priority_rank INT NULL,
        source_kind VARCHAR(20) NOT NULL DEFAULT '',
        source_key VARCHAR(255) NOT NULL DEFAULT '',
        rev INT NOT NULL DEFAULT 0,
        doc LONGTEXT NOT NULL,
        KEY idx_status (status), KEY idx_team (team), KEY idx_seq (seq)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS task_assets (
        task_id VARCHAR(40) NOT NULL,
        asset VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
        state VARCHAR(20) NOT NULL DEFAULT '',
        team VARCHAR(100) NOT NULL DEFAULT '',
        PRIMARY KEY (task_id, asset), KEY idx_asset (asset)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS task_qids (
        task_id VARCHAR(40) NOT NULL,
        qid VARCHAR(20) NOT NULL,
        PRIMARY KEY (task_id, qid), KEY idx_qid (qid)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS notes (
        id VARCHAR(40) NOT NULL PRIMARY KEY,
        seq INT NOT NULL,
        asset VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '',
        qid VARCHAR(20) NOT NULL DEFAULT '',
        at VARCHAR(40) NOT NULL DEFAULT '',
        by_user VARCHAR(100) NOT NULL DEFAULT '',
        deleted TINYINT(1) NOT NULL DEFAULT 0,
        doc LONGTEXT NOT NULL,
        KEY idx_asset (asset), KEY idx_seq (seq)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS review_queue (
        id VARCHAR(80) NOT NULL PRIMARY KEY,
        seq INT NOT NULL,
        name VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '',
        status VARCHAR(20) NOT NULL DEFAULT '',
        suggested_owner VARCHAR(100) NOT NULL DEFAULT '',
        doc LONGTEXT NOT NULL,
        KEY idx_name (name), KEY idx_status (status), KEY idx_seq (seq)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
]
# children first when emptying
ALL = ["review_queue", "notes", "task_qids", "task_assets", "tasks", "risk_acceptance_qids", "risk_acceptances", "findings", "vuln_cves", "vulns", "assets"]


# ---------------------------------------------------------------- value helpers: typed columns, never fail on odd data
def s(v, n):
    if v is None or isinstance(v, (dict, list)):
        return ""
    if isinstance(v, bool):
        v = "true" if v else "false"
    return str(v)[:n]


def b(v):
    return 1 if v is True or v == 1 or v == "true" else 0


def i(v, lo=-2 ** 31, hi=2 ** 31 - 1):
    try:
        x = int(v) if not isinstance(v, bool) else None
        return x if x is not None and lo <= x <= hi and float(v) == x else None
    except (TypeError, ValueError):
        return None


def f(v):
    try:
        return float(v) if v not in (None, "", True, False) else 0.0
    except (TypeError, ValueError):
        return 0.0


def dumps(d):
    return json.dumps(d, separators=(",", ":"), ensure_ascii=False)


def cve_id(c):
    return s(c.get("id") if isinstance(c, dict) else c, 40).upper()


# ---------------------------------------------------------------- row builders (one place: rebuild and later writes use the same)
def asset_row(seq, d):
    return (s(d.get("normalizedName"), 255), seq, s(d.get("originalName"), 255), s(d.get("owner"), 100), s(d.get("service"), 120), s(d.get("status"), 30),
            s(d.get("environment"), 30), s(d.get("exposure"), 30), i(d.get("tier"), 0, 9), s(d.get("ha"), 1), s(d.get("os"), 255), s(d.get("osLifecycle"), 40),
            s(d.get("ipv4Address"), 100), s(d.get("lastSeen"), 40), s(d.get("riskStatus"), 30), b(d.get("unrecognised")), b(d.get("patchNA")), dumps(d))


def finding_row(d):
    return (s(d.get("k"), 512), s(d.get("asset"), 255), s(d.get("qid"), 20), s(d.get("status"), 20), i(d.get("sev"), -128, 127) or 0, f(d.get("qvs")), f(d.get("cvss")),
            s(d.get("port"), 20), s(d.get("first"), 40), s(d.get("last"), 40), b(d.get("patchable")), dumps(d))


def vuln_row(d):
    return (s(d.get("qid"), 20), s(d.get("title"), 500), s(d.get("category"), 100), i(d.get("sev"), -128, 127) or 0, f(d.get("cvss")), b(d.get("patchable")),
            s(d.get("published"), 40), s(d.get("patchReleased"), 60), dumps(d))


def ra_row(seq, d):
    return (s(d.get("id"), 80), seq, s(d.get("asset"), 255), s(d.get("scope"), 20), s(d.get("status"), 30), s(d.get("accDate"), 40), s(d.get("revDate"), 40), s(d.get("expDate"), 40), dumps(d))


def task_row(seq, d):
    src = d.get("source") if isinstance(d.get("source"), dict) else {}
    return (s(d.get("id"), 40), seq, s(d.get("type"), 20), s(d.get("status"), 40), s(d.get("team"), 100), s(d.get("assignee"), 100), s(d.get("due"), 40),
            i(d.get("priorityRank")), s(src.get("kind"), 20), s(src.get("key"), 255), i(d.get("rev")) or 0, dumps(d))


def note_row(seq, d):
    return (s(d.get("id"), 40), seq, s(d.get("asset"), 255), s(d.get("qid"), 20), s(d.get("at"), 40), s(d.get("by"), 100), b(d.get("deleted")), dumps(d))


def queue_row(seq, d):
    return (s(d.get("id"), 80), seq, s(d.get("normalizedName"), 255), s(d.get("status"), 20), s(d.get("suggestedOwner"), 100), dumps(d))


COLLECTIONS = {   # old collection -> (table, key field, row builder)
    "gov_asset_register": ("assets", "normalizedName", asset_row),
    "gov_risk_acceptances": ("risk_acceptances", "id", ra_row),
    "gov_remediation": ("tasks", "id", task_row),
    "gov_asset_notes": ("notes", "id", note_row),
    "gov_review_queue": ("review_queue", "id", queue_row),
}
INSERT = {
    "assets": "INSERT INTO assets (name, seq, original_name, owner, service, status, environment, exposure, tier, ha, os, os_lifecycle, ipv4, last_seen, risk_status, unrecognised, patch_na, doc) VALUES (" + ",".join(["%s"] * 18) + ")",
    "findings": "INSERT INTO findings (k, asset, qid, status, sev, qvs, cvss, port, first_found, last_found, patchable, doc) VALUES (" + ",".join(["%s"] * 12) + ")",
    "vulns": "INSERT INTO vulns (qid, title, category, sev, cvss, patchable, published, patch_released, doc) VALUES (" + ",".join(["%s"] * 9) + ")",
    "risk_acceptances": "INSERT INTO risk_acceptances (id, seq, asset, scope, status, acc_date, rev_date, exp_date, doc) VALUES (" + ",".join(["%s"] * 9) + ")",
    "tasks": "INSERT INTO tasks (id, seq, type, status, team, assignee, due, priority_rank, source_kind, source_key, rev, doc) VALUES (" + ",".join(["%s"] * 12) + ")",
    "notes": "INSERT INTO notes (id, seq, asset, qid, at, by_user, deleted, doc) VALUES (" + ",".join(["%s"] * 8) + ")",
    "review_queue": "INSERT INTO review_queue (id, seq, name, status, suggested_owner, doc) VALUES (" + ",".join(["%s"] * 6) + ")",
}


def create(cur):
    for t in TABLES:
        cur.execute(t)


def _many(cur, sql, rows, n=1000):
    for k in range(0, len(rows), n):
        cur.executemany(sql, rows[k:k + n])


def _unique(rows, key=0):
    """The old storage never forced unique keys inside a collection; keep the first and count the rest."""
    seen, out, dup = set(), [], 0
    for r in rows:
        if r[key] in seen or r[key] == "":
            dup += 1
            continue
        seen.add(r[key]); out.append(r)
    return out, dup


def rebuild(cur):
    """Empty the new tables and fill them from the old storage. Call inside one transaction (conn_ctx): the old
    data is read in one consistent snapshot, and either everything is rebuilt or nothing changes."""
    t0 = time.time()
    create(cur)
    for t in ALL:
        cur.execute(f"DELETE FROM {t}")
    counts, skipped = {}, {}
    for coll, (table, keyf, row) in COLLECTIONS.items():
        cur.execute("SELECT seq, doc FROM records WHERE collection=%s ORDER BY seq", (coll,))
        docs = [(seq, json.loads(doc)) for seq, doc in cur.fetchall()]
        rows, dup = _unique([row(seq, d) for seq, d in docs if isinstance(d, dict)])
        _many(cur, INSERT[table], rows)
        counts[table], skipped[table] = len(rows), dup + sum(1 for _, d in docs if not isinstance(d, dict))
        if table == "risk_acceptances":
            kids = {(s(d.get("id"), 80), s(q, 20)) for _, d in docs if isinstance(d, dict) for q in (d.get("qids") or []) if q not in (None, "")}
            _many(cur, "INSERT IGNORE INTO risk_acceptance_qids (ra_id, qid) VALUES (%s,%s)", sorted(kids))
            counts["risk_acceptance_qids"] = len(kids)
        if table == "tasks":
            ta, tq = {}, set()
            for _, d in docs:
                if not isinstance(d, dict):
                    continue
                tid = s(d.get("id"), 40)
                for a in d.get("assets") or []:
                    if isinstance(a, dict) and a.get("name"):
                        ta.setdefault((tid, s(a.get("name"), 255)), (s(a.get("state"), 20), s(a.get("team"), 100)))
                src = d.get("source") if isinstance(d.get("source"), dict) else {}
                for q in src.get("qids") or []:
                    tq.add((tid, s(q, 20)))
            _many(cur, "INSERT INTO task_assets (task_id, asset, state, team) VALUES (%s,%s,%s,%s)", [(k[0], k[1], v[0], v[1]) for k, v in ta.items()])
            _many(cur, "INSERT INTO task_qids (task_id, qid) VALUES (%s,%s)", sorted(tq))
            counts["task_assets"], counts["task_qids"] = len(ta), len(tq)
    cur.execute("SELECT doc FROM qids")
    qd = [json.loads(r[0]) for r in cur.fetchall()]
    rows, dup = _unique([vuln_row(d) for d in qd])
    _many(cur, INSERT["vulns"], rows)
    counts["vulns"], skipped["vulns"] = len(rows), dup
    vc = {}
    for d in qd:
        for c in d.get("cves") or []:
            cid = cve_id(c)
            if cid:
                vc.setdefault((s(d.get("qid"), 20), cid), f(c.get("cvss")) if isinstance(c, dict) else 0.0)
    _many(cur, "INSERT INTO vuln_cves (qid, cve, cvss) VALUES (%s,%s,%s)", [(k[0], k[1], v) for k, v in vc.items()])
    counts["vuln_cves"] = len(vc)
    cur.execute("SELECT doc FROM detections")
    rows = [finding_row(json.loads(r[0])) for r in cur.fetchall()]
    _many(cur, INSERT["findings"], rows, 2000)
    counts["findings"] = len(rows)
    meta = {"schemaVersion": SCHEMA_VERSION, "builtAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seconds": round(time.time() - t0, 2), "counts": counts, "skipped": {k: v for k, v in skipped.items() if v}}
    cur.execute("REPLACE INTO schema_meta (k, v) VALUES ('build', %s)", (dumps(meta),))
    return meta


def verify(cur):
    """Prove the new tables hold exactly what the old storage holds. Returns {ok, checks: [{name, ok, detail}]}."""
    checks = []

    def check(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    for coll, (table, keyf, row) in COLLECTIONS.items():
        cur.execute("SELECT doc FROM records WHERE collection=%s ORDER BY seq", (coll,))
        old = [json.loads(r[0]) for r in cur.fetchall()]
        cur.execute(f"SELECT doc FROM {table} ORDER BY seq")
        new = [json.loads(r[0]) for r in cur.fetchall()]
        check(f"{coll} -> {table}: every document back identical, in order", old == new, f"{len(old)} old, {len(new)} new")
        cur.execute(f"SELECT * FROM {table} ORDER BY seq")
        cols = [c[0] for c in cur.description]
        bad = 0
        for r in cur.fetchall():
            rec = dict(zip(cols, r))
            d = json.loads(rec["doc"])
            built = dict(zip(cols, row(rec["seq"], d)))
            if any(built[c] != rec[c] and not (isinstance(rec[c], float) and abs(built[c] - rec[c]) < 1e-6) for c in cols if c != "doc"):
                bad += 1
        check(f"{table}: every column agrees with its document", bad == 0, f"{bad} rows disagree" if bad else "")
    cur.execute("SELECT doc FROM detections")
    old = sorted(r[0] for r in cur.fetchall())
    cur.execute("SELECT doc FROM findings")
    new = sorted(r[0] for r in cur.fetchall())
    check("detections -> findings: every finding back identical", [json.loads(x) for x in old] == [json.loads(x) for x in new] if len(old) == len(new) else False, f"{len(old)} old, {len(new)} new")
    cur.execute("SELECT COUNT(*) FROM findings f JOIN detections d ON d.k = f.k WHERE d.asset <> f.asset OR d.qid <> f.qid OR d.sev <> f.sev OR ABS(d.qvs - f.qvs) > 0.0001")
    check("findings: asset, QID, severity and QVS agree with the old columns", cur.fetchone()[0] == 0)
    cur.execute("SELECT doc FROM qids")
    oq = {json.loads(r[0])["qid"]: json.loads(r[0]) for r in cur.fetchall()}
    cur.execute("SELECT qid, doc FROM vulns")
    nq = {r[0]: json.loads(r[1]) for r in cur.fetchall()}
    check("qids -> vulns: every QID back identical", oq == nq, f"{len(oq)} old, {len(nq)} new")
    want = {(q, cve_id(c)) for q, d in oq.items() for c in (d.get("cves") or []) if cve_id(c)}
    cur.execute("SELECT qid, cve FROM vuln_cves")
    check("vuln_cves: one row per CVE of each QID", set(cur.fetchall()) == want, f"{len(want)} expected")
    cur.execute("SELECT doc FROM records WHERE collection='gov_remediation'")
    tasks = [json.loads(r[0]) for r in cur.fetchall()]
    want = {(t.get("id"), a.get("name")) for t in tasks for a in (t.get("assets") or []) if isinstance(a, dict) and a.get("name")}
    cur.execute("SELECT task_id, asset FROM task_assets")
    check("task_assets: one row per machine of each task", set(cur.fetchall()) == want, f"{len(want)} expected")
    cur.execute("SELECT COUNT(*) FROM findings f LEFT JOIN vulns v ON v.qid = f.qid WHERE v.qid IS NULL")
    orphans = cur.fetchone()[0]
    checks.append({"name": "findings whose QID is not in the catalogue (information, not an error)", "ok": True, "detail": str(orphans)})
    cur.execute("SELECT COUNT(DISTINCT f.asset) FROM findings f LEFT JOIN assets a ON a.name = f.asset WHERE a.name IS NULL")
    checks.append({"name": "machines with findings but not in the register (information, not an error)", "ok": True, "detail": str(cur.fetchone()[0])})
    ok = all(c["ok"] for c in checks)
    cur.execute("REPLACE INTO schema_meta (k, v) VALUES ('verify', %s)", (dumps({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "ok": ok, "checks": checks}),))
    return {"ok": ok, "checks": checks}


def status(cur):
    create(cur)
    cur.execute("SELECT k, v FROM schema_meta")
    return {k: json.loads(v) for k, v in cur.fetchall()}
