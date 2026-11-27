"""Database stage 3 (v4.44): the CyberView status rules on the server, so questions can be answered without the browser
downloading every finding.

This is a line-for-line port of the browser's rules in app.js. Keep them together:

    PriorityEngine.isExploited / tier            -> is_exploited(), finding_tier()
    StatusEngine.DEFAULTS / settings()           -> STATUS_DEFAULTS, status_settings()
    RemediationService.SLA_DEFAULT / sla()       -> SLA_DEFAULT, sla()
    StatusEngine.tierOf / effTier / isHigh / findingTier / priority / due / time
    StatusEngine.exIndex / effRisk, RiskView.machine
    App.getVulnWhole + scopedData({official: true, whole: true})   -> scope()

The golden tests prove they agree: tests/golden/golden.py server compares, for every finding, the tier, priority,
due date, backlog, overdue and exploited flag the browser works out with what this module works out (and the
constants themselves, so a change to one side without the other fails the build).

Known difference: a date written without a time zone (e.g. "2026-05-19 10:00:00") is read as local time by a browser
and as UTC here. Qualys API dates carry a zone; the golden fixture uses them. Check live data before relying on it.
"""
import json
import re
import time
from datetime import datetime, timezone

DAY = 86400000
EXPLOITED = ["CISA Known Exploited Vulnerabilities", "Active Attacks", "Ransomware", "Wormable", "Zero Day"]
QVS_SPRINT, QVS_SCHEDULED = 70, 40
STATUS_DEFAULTS = {
    "matrix": {"1": [1, 1, 2], "2": [2, 2, 3], "3": [3, 3, 4], "4": [4, 4, 4]},
    "internetStep": True,
    "internetDays": 0,
    "epssThreshold": 0.97,
    "highSevP2": False,
    "goLive": "",
    "backlogTargets": {"1": 60, "2": 90, "3": 90, "4": 180},
}
SLA_DEFAULT = {"t1": 14, "t2": 30, "t3": 90, "t4": 180}


def constants():
    """What the golden test compares with the browser's own constants."""
    return {"exploited": EXPLOITED, "qvsSprint": QVS_SPRINT, "qvsScheduled": QVS_SCHEDULED, "statusDefaults": STATUS_DEFAULTS, "slaDefault": SLA_DEFAULT}


# ---------------------------------------------------------------- small helpers with the browser's semantics
def to_ms(v):
    """StatusEngine.time: a date string to epoch milliseconds, 0 when it cannot be read."""
    if not v:
        return 0
    s = re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", str(v).strip())
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
            d = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        else:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)          # the browser would use its local zone here (see the module note)
        return int(round(d.timestamp() * 1000))
    except ValueError:
        return 0


def num(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def today_iso(now_ms):
    return datetime.fromtimestamp(now_ms / 1000, timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------- settings
def status_settings(stored):
    o = stored if isinstance(stored, dict) else {}
    S = {**STATUS_DEFAULTS, **o}
    S["matrix"] = {**STATUS_DEFAULTS["matrix"], **{str(k): v for k, v in (o.get("matrix") or {}).items()}}
    S["backlogTargets"] = {**STATUS_DEFAULTS["backlogTargets"], **{str(k): v for k, v in (o.get("backlogTargets") or {}).items()}}
    th = o.get("epssThreshold", STATUS_DEFAULTS["epssThreshold"])
    S["_epssTh"] = num(th) if 0 <= num(th, -1) <= 1 else 0          # PriorityEngine.setEpssThreshold
    return S


def sla(stored_remediation_settings):
    o = stored_remediation_settings if isinstance(stored_remediation_settings, dict) else {}
    return {**SLA_DEFAULT, **(o.get("sla") or {})}


# ---------------------------------------------------------------- the rules
def is_exploited(q):
    return bool(q.get("kev")) or any(t in EXPLOITED for t in (q.get("rti") or []))


def finding_tier(d, q, S):
    """PriorityEngine.tier: 1 Fix now (exploited), 2 This sprint, 3 Scheduled, 4 Routine; very likely exploited (EPSS) one more urgent."""
    rti = q.get("rti") or []
    qvs = num(d.get("qvs"))
    if is_exploited(q):
        t = 1
    elif qvs >= QVS_SPRINT or ("Remote Code Execution" in rti and "Public Exploit" in rti):
        t = 2
    elif num(d.get("sev")) >= 5 or qvs >= QVS_SCHEDULED:
        t = 3
    else:
        t = 4
    e = q.get("epss") or 0
    if S["_epssTh"] > 0 and e >= S["_epssTh"]:
        t = max(1, t - 1)
    return t


def tier_of(r):
    try:
        t = int((r or {}).get("tier")) if not isinstance((r or {}).get("tier"), bool) else 0
    except (TypeError, ValueError):
        return 0
    return t if t in (1, 2, 3) and num((r or {}).get("tier")) == t else 0


def eff_tier(r):
    return tier_of(r) or 2


def is_high(d):
    cv = num(d.get("cvss"))
    return cv >= 7 if cv > 0 else num(d.get("sev")) >= 4


def status_tier(d, tier, S):
    return min(tier, 2) if (S.get("highSevP2") and d.get("patchable") and is_high(d)) else tier


def priority(ftier, r, S):
    row = S["matrix"].get(str(ftier)) or S["matrix"]["4"]
    et = eff_tier(r)
    p = row[et - 1] if len(row) >= et and row[et - 1] else 4
    if S.get("internetStep") and r and r.get("exposure") == "Internet Facing":
        p = max(1, p - 1)
    return p


def due(d, p, S, SLA, r, now_ms):
    first = to_ms(d.get("first")) or now_ms
    live = to_ms(S.get("goLive"))
    if live and first < live:
        return True, live + (num(S["backlogTargets"].get(str(p)), 0) or 180) * DAY
    days = num(SLA.get("t" + str(p)), 0) or 180
    if num(S.get("internetDays")) > 0 and p <= 2 and r and r.get("exposure") == "Internet Facing":
        days = min(days, num(S["internetDays"]))
    return False, first + days * DAY


def ex_index(acceptances, now_ms):
    """StatusEngine.exIndex: in-date acceptances by machine (whole machine, or per finding by QID)."""
    today, by = today_iso(now_ms), {}
    for a in acceptances or []:
        if not isinstance(a, dict) or a.get("status") != "Risk Accepted" or not a.get("asset"):
            continue
        e = by.setdefault(a["asset"], {"whole": None, "qids": set(), "expired": []})
        if a.get("expDate") and a["expDate"] < today:
            e["expired"].append(a)
            continue
        if a.get("scope") == "finding":
            e["qids"].update(str(q) for q in (a.get("qids") or []))
        else:
            e["whole"] = a
    return by


def machine_accepted(r, ex):
    rs = (r or {}).get("riskStatus") or "Open"
    if rs != "Risk Accepted":
        return False
    e = ex.get(r.get("normalizedName"))
    return not (e and not e["whole"] and any(a.get("scope") != "finding" for a in e["expired"]))


# ---------------------------------------------------------------- the data, read from the relational tables
def load(cur, kev=None, epss=None):
    """Everything the rules need, read once. kev: set of CVE ids; epss: {cve: score}."""
    cur.execute("SELECT doc FROM assets ORDER BY seq")
    register = [json.loads(r[0]) for r in cur.fetchall()]
    cur.execute("SELECT doc FROM risk_acceptances ORDER BY seq")
    acceptances = [json.loads(r[0]) for r in cur.fetchall()]
    settings = {}
    for coll in ("gov_status_settings", "gov_remediation_settings"):
        cur.execute("SELECT doc FROM records WHERE collection=%s ORDER BY seq LIMIT 1", (coll,))
        r = cur.fetchone()
        settings[coll] = json.loads(r[0]) if r else {}
    cur.execute("SELECT doc FROM vulns")
    qmap = {}
    for (raw,) in cur.fetchall():
        q = json.loads(raw)
        qmap[str(q.get("qid"))] = q
    cur.execute("SELECT doc FROM findings")
    dets = [json.loads(r[0]) for r in cur.fetchall()]
    kev, epss = kev or set(), epss or {}
    for q in qmap.values():                       # Epss.attach: highest EPSS of the QID's CVEs, on the KEV list if any CVE is
        ids = [str(c.get("id") if isinstance(c, dict) else c).upper() for c in (q.get("cves") or [])]
        q["epss"] = max([epss.get(c, 0) for c in ids] or [0])
        q["kev"] = any(c in kev for c in ids)
    return {"register": register, "acceptances": acceptances, "S": status_settings(settings["gov_status_settings"]),
            "sla": sla(settings["gov_remediation_settings"]), "qmap": qmap, "dets": dets}


def annotate(D, now_ms):
    """App.getVulnWhole + StatusEngine.annotate: the open findings that count, each with tier, p, due, backlog, overdue."""
    S, SLA, qmap = D["S"], D["sla"], D["qmap"]
    reg = {r.get("normalizedName"): r for r in D["register"] if isinstance(r, dict)}
    retired = {n for n, r in reg.items() if r.get("status") == "Retired"}
    ex = ex_index(D["acceptances"], now_ms)
    out = []
    for d in D["dets"]:
        if re.fullmatch(r"fixed", str(d.get("status") or "").strip(), re.I):
            continue
        if d.get("asset") in retired:
            continue
        e = ex.get(d.get("asset"))
        if e and str(d.get("qid")) in e["qids"]:
            continue                                 # an in-date per-finding exception: never counted
        q = qmap.get(str(d.get("qid"))) or {}
        t = finding_tier(d, q, S)
        r = reg.get(d.get("asset"))
        p = priority(status_tier(d, t, S), r, S)
        backlog, du = due(d, p, S, SLA, r, now_ms)
        out.append({"k": d.get("k"), "asset": d.get("asset"), "qid": str(d.get("qid")), "tier": t, "p": p, "due": int(du), "backlog": backlog,
                    "overdue": du < now_ms, "exploited": is_exploited(q), "epss": q.get("epss") or 0, "sev": d.get("sev"), "qvs": d.get("qvs"),
                    "patchable": bool(d.get("patchable")), "first": d.get("first"), "_doc": d})
    return out, reg, ex


def scope(D, team, now_ms, ann=None, official=True):
    """scopedData({owner: team, official: true, whole: true}): the team's live machines, without risk-accepted machines.
    ann: annotate(D, now_ms) worked out already (the server caches it)."""
    found, reg, ex = ann or annotate(D, now_ms)
    live = [r for r in D["register"] if isinstance(r, dict) and r.get("status") != "Retired"]
    team_scope = [r for r in live if team == "ALL" or r.get("owner") == team]
    accepted = {r.get("normalizedName") for r in team_scope if official and machine_accepted(r, ex)}
    names = {r.get("normalizedName") for r in team_scope} - accepted
    dets = [f for f in found if f["asset"] in names]
    return dets, {"machines": len(accepted & {f["asset"] for f in found})}


def full_row(f):
    """The finding as stored, with the server's answers on top (tier, p, due, backlog, overdue, exploited, epss): what a page
    needs to show it and to apply any other priority model to it."""
    return {**f["_doc"], **{k: v for k, v in f.items() if k != "_doc"}}


def public(f):
    return {k: v for k, v in f.items() if k != "_doc"}


def summary(dets):
    by = lambda key: {k: sum(1 for d in dets if key(d) == k) for k in sorted({key(d) for d in dets})}
    return {
        "findings": len(dets), "machines": len({d["asset"] for d in dets}),
        "byP": by(lambda d: "P%d" % d["p"]), "byTier": by(lambda d: "T%d" % d["tier"]),
        "overdue": sum(1 for d in dets if d["overdue"]), "backlog": sum(1 for d in dets if d["backlog"]),
        "exploited": sum(1 for d in dets if d["exploited"]), "fixes": len({d["qid"] for d in dets}),
    }


def worklist(dets, qmap):
    """One row per fix (QID), worst first: what the new site's Work list shows (CyberView status rules)."""
    g = {}
    for d in dets:
        x = g.setdefault(d["qid"], {"qid": d["qid"], "p": 9, "due": 0, "overdue": 0, "findings": 0, "machines": set(), "exploited": d["exploited"], "epss": d["epss"]})
        x["p"] = min(x["p"], d["p"])
        x["due"] = d["due"] if not x["due"] else min(x["due"], d["due"])
        x["overdue"] += 1 if d["overdue"] else 0
        x["findings"] += 1
        x["machines"].add(d["asset"])
    out = []
    for x in g.values():
        q = qmap.get(x["qid"]) or {}
        out.append({**x, "machines": len(x["machines"]), "title": q.get("title") or "QID " + x["qid"], "kev": bool(q.get("kev")), "patchable": bool(q.get("patchable")),
                    "cves": [c.get("id") if isinstance(c, dict) else c for c in (q.get("cves") or [])][:5]})
    out.sort(key=lambda x: (x["p"], -(x["overdue"] > 0), -x["machines"], x["qid"]))
    return out


def vectors(dets):
    """The per-finding answer the golden test compares with the browser, one line each."""
    return sorted(f"{d['k']}|T{d['tier']}|P{d['p']}|{d['due']}|{int(d['backlog'])}|{int(d['overdue'])}|{int(d['exploited'])}" for d in dets)


def now_ms():
    return int(time.time() * 1000)
