// Golden probe (tests/golden): the numbers each page shows, read through the app's own code, as plain JSON.
// Run in the page by golden.py: goldenClassic() on index.html, goldenNew() on new/index.html.
// Anything that must stay the same through the database work (stages 1-5) belongs here; nothing here changes data.
(() => {
    const T = Date.now;                                   // the frozen clock
    const count = (arr, f) => arr.reduce((m, x) => { const k = String(f(x)); m[k] = (m[k] || 0) + 1; return m; }, {});
    const sortObj = (o) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => a.localeCompare(b)));
    const day = (t) => t ? new Date(t).toISOString().slice(0, 10) : '';

    async function teamNumbers(team) {
        const sd = await app.scopedData({ owner: team, official: true, whole: true });
        const d = sd.dets;
        const groups = PriorityEngine.fixGroups(d, sd.vd.qmap).sort(App.vulnFixCmp);
        const fams = PriorityEngine.familyGroups(PriorityEngine.fixGroups(d, sd.vd.qmap), sd.vd.qmap, App.vulnFixCmp);
        let plan = null;
        try {
            const PB = await app.planBuckets(team, 'ALL', true, true);
            if (PB) plan = Object.fromEntries(Object.entries(PB.B).map(([k, v]) => [k, v.length]));
        } catch (e) { plan = 'error: ' + e.message; }
        return {
            findings: d.length,
            machines: new Set(d.map(x => x.asset)).size,
            byP: sortObj(count(d, x => 'P' + (x.p || '-'))),
            byTier: sortObj(count(d, x => 'T' + x.tier)),
            overdue: d.filter(x => x.overdue).length,
            backlog: d.filter(x => x.backlog).length,
            exploited: d.filter(x => x.exploited).length,
            hidden: sd.hidden,
            fixes: groups.length,
            families: fams.length,
            topFixes: groups.slice(0, 15).map(g => `${g.qid}|P${g.p || '-'}|${g.assets.size}|${day(g.due)}`),
            assetOrder: sd.assets.slice(0, 15).map(a => `${a.name}|P${a.worstP}|${a.detections}`),
            plan,
        };
    }

    window.goldenClassic = async function () {
        const out = { clock: new Date(T()).toISOString() };
        const all = StorageService.peek(StorageService.KEYS.ASSET_REGISTER), live = StorageService.live();
        out.register = {
            all: all.length, live: live.length, retired: all.length - live.length,
            unrecognised: live.filter(r => r.unrecognised).length,
            byTeam: sortObj(count(live, r => r.owner || 'Unknown')),
            byTier: sortObj(count(live, r => StatusEngine.tierCode(r) || 'unset')),
            byExposure: sortObj(count(live, r => r.exposure || 'Unknown')),
            byService: sortObj(count(live, r => r.service || 'Unclassified')),
        };
        const q = ReviewQueueService.getQueue() || [];
        out.reviewQueue = sortObj(count(q, x => x.status));
        const vd = await app.getVulnData({ whole: true });
        out.findings = {
            stored: vd.all.length, open: vd.dets.length, excepted: vd.excepted.length,
            retired: [...vd.retiredBy.values()].reduce((n, l) => n + l.length, 0),
            qids: vd.qmap.size, qidsKev: [...vd.qmap.values()].filter(x => x.kev).length, qidsEpss: [...vd.qmap.values()].filter(x => x.epss > 0).length,
            byStatus: sortObj(count(vd.all, x => x.status)),
        };
        out.teams = {};
        for (const t of ['ALL', ...OrgSettings.teams()]) out.teams[t] = await teamNumbers(t);
        try {
            const st = await app.statusData();
            out.status = Object.fromEntries(st.teams.map(t => [t.team, { word: t.word, assets: t.assets, compliance: t.compliance, newP12: t.newP12, newIn: t.newIn, over12: t.over12, bl12: t.bl12, blOver: t.blOver, coverage: t.coverage, tierGap: t.tierGap, unsupported: t.unsupported }]));
        } catch (e) { out.status = 'error: ' + e.message; }
        const stl = app.stale();
        out.notSeen = { list: stl.list.size, counts: sortObj(stl.counts) };
        const tasks = RemediationService.list();
        out.tasks = { total: tasks.length, byStatus: sortObj(count(tasks, t => t.status)), assets: tasks.reduce((n, t) => n + (t.assets || []).length, 0) };
        const ra = StorageService.peek(StorageService.KEYS.RISK_ACCEPTANCES) || [];
        out.riskAcceptances = sortObj(count(ra, a => `${a.scope || 'asset'}|${a.status}`));
        out.statusHistory = (StorageService.peek(StorageService.KEYS.STATUS_HISTORY) || []).length;
        return out;
    };

    // v4.44 stage 3: what the server's rules (server/rules.py) must reproduce, finding by finding, and the constants they use
    window.goldenVectors = async function (teams) {
        const out = {};
        for (const t of teams) {
            const sd = await app.scopedData({ owner: t, official: true, whole: true });
            out[t] = sd.dets.map(d => `${d.k}|T${d.tier}|P${d.p}|${Math.round(d.due)}|${d.backlog ? 1 : 0}|${d.overdue ? 1 : 0}|${d.exploited ? 1 : 0}`).sort();
        }
        return out;
    };
    window.goldenConstants = function () {
        const D = StatusEngine.DEFAULTS, sla = RemediationService.SLA_DEFAULT;
        return { exploited: PriorityEngine.EXPLOITED, qvsSprint: PriorityEngine.QVS_SPRINT, qvsScheduled: PriorityEngine.QVS_SCHEDULED,
            statusDefaults: { matrix: Object.fromEntries(Object.entries(D.matrix).map(([k, v]) => [String(k), v])), internetStep: D.internetStep, internetDays: D.internetDays,
                epssThreshold: D.epssThreshold, highSevP2: D.highSevP2, goLive: D.goLive, backlogTargets: Object.fromEntries(Object.entries(D.backlogTargets).map(([k, v]) => [String(k), v])) },
            slaDefault: { t1: sla.t1, t2: sla.t2, t3: sla.t3, t4: sla.t4 } };
    };

    window.goldenNew = async function () {
        const out = { clock: new Date(T()).toISOString(), presets: {} };
        const teams = ['ALL', ...OrgSettings.teams()];
        const saved = UI.saved;
        for (const t of teams) {
            UI.team = t; UI.stale = true;
            const D = await UI.load();
            for (const p of PriorityModel.PRESETS) {
                const M = { ...structuredClone(saved), preset: p.id };
                const sc = UI.scored(M, D), g = UI.groups(sc, D, true), g1 = UI.groups(sc, D, false);
                const k = `${t}|${p.id}`;
                out.presets[k] = {
                    byP: sortObj(count(sc, x => 'P' + x.e.p)),
                    overdue: sc.filter(x => x.e.due && x.e.due < T()).length,
                    rows: g.length, rowsUngrouped: g1.length,
                    top: g.slice(0, 10).map(x => `${x.key}|P${x.p}|${x.machines.size}|${day(x.due)}`),
                    whoFixes: D.plan ? sortObj(g.reduce((m, x) => { Object.entries(x.ax).forEach(([b, n]) => { m[b] = (m[b] || 0) + n; }); return m; }, {})) : null,
                };
            }
        }
        UI.team = teams[0];
        const G = UI.gaps();
        out.machines = { queue: G.queue.length, noteam: G.noteam.length, notier: G.notier.length, noexp: G.noexp.length, unseen: G.unseen.length };
        const SB = app.queueSeen();
        out.seenBy = sortObj(count([...SB.by.values()], e => e.all ? 'all-missing' : e.miss.length ? 'missing:' + e.miss.join('+') : 'seen'));
        const H = UI.histPts('ALL');
        out.trend = { points: H.length, last: H.length ? H[H.length - 1] : null };
        return out;
    };
})();
