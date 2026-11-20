# CyberView

**Stop drowning in findings. Start fixing what matters.**

CyberView turns your scanner output into a short, ranked to-do list, team by team.

## Feed it

- **Qualys:** every finding, pulled read-only from the API each morning, or a CSV export.
- **Automox:** agents, failing policies and waiting patches, read-only.
- **End-of-life dates:** from the endoflife.date API, including paid extended-support dates, plus your own dates where you know better.
- **Your people:** who owns each machine, how critical it is (Tier 1–3) and whether it faces the Internet, set once in the Asset Register. New machines arrive in a Review Queue with an owner already suggested.

## It joins the dots

- One machine, one record: Qualys, Automox and the register are matched by asset ID, name or IP. Where Qualys and Automox disagree about a machine's operating system, it lands in the Review Queue to settle.
- Every finding gets a **priority (P1–P4)** from how dangerous it is and how critical the machine is, with Internet-facing machines one step more urgent. Then a **due date**.
- One settings page, **Organisation setup**: teams, tiers, name matching and the status rules. Choose a built-in rule set: **Standard**, or **UK** (NCSC and Cyber Essentials deadlines, 5 days for Internet-facing).
- Tasks and accepted risks are tracked against the same data, and each morning's sync ticks fixes off automatically. One **⚑ Risk-accepted** switch hides or shows accepted risk on every page; status and targets never count it (a whole accepted machine's OS support and Automox checks don't count either; its scanning still does), and machine lists never include it.

## What you get

- **Simple view** (the default): just the Dashboard, Patch Plan, CVE Lookup, Team Risk Report and End of Life Report. **Advanced** opens every page and setting.
- **Patch Plan:** every open finding set against Automox: what's patched, what Automox will patch in the next 7 days, what's blocked, and the gap that needs manual remediation, with machine lists for Ansible.
- **CVE Lookup:** paste the CVE the cyber team sent: every machine with it open, and for each one whether Automox will patch it (and when), the Automox patch is blocked, or it needs a manual fix. Then a machine list, a task, or a summary to paste into your reply. If no Qualys finding names the CVE it says so, rather than "not affected". Tick machines and press **⚖️ Accept risk** to record an exception for just those. **⟳ Refresh this CVE** asks Qualys and Automox there and then, and shows what is newly found and what is fixed. **📌 Pin** a CVE to watch it: its count is tracked after every sync, with a target date and a ready-made update for the cyber team. For RHEL machines it also shows **what Red Hat says**: the fix package per release, or *not affected* (worth checking when Qualys flags it).
- **👥 Team (sidebar):** choose your team once; every report and plan page shows it.
- **Services** come from a list (Organisation setup → Services, first built from your data); merge stray spellings there.
- **HA sides:** tiers are 1A/1B, 2A/2B, 3A/3B: patch side A one day and side B the next; machine lists offer each side as its own download. Priorities ignore the side.
- **Spot a wrong owner?** Press **✎** next to the machine's name (or right-click it) to change its team there and then. **Click any column heading** to sort a table.
- **💬 Comments:** note what you know about a machine (or one finding on it) on the machine's page; a **💬 n** marker shows it wherever the machine appears. Each comment shows who wrote it and when; edits keep the earlier wording.
- **Data Health:** every data source with when it last synced, when it syncs next and a **Sync now** button, plus the machines with no team, tier or service.
- **Vuln Management:** *Machines to fix first* and *Fixes that clear the most*, with one-click machine lists ready for Ansible.
- **Status:** one headline per team (On track / Slipping / Behind), with trend charts.
- **Team Risk Report:** a print-ready report per team: its status, the machines and fixes to do first, its Patch Plan, data gaps and recommended actions.
- **End of Life · Patch Coverage · Remediation:** what to upgrade, what isn't being patched (no Automox agent, or an agent but no patch policy), and who is fixing what by when.
- **Dashboard:** every team's status, this week's Patch Plan, end-of-life machines and how fresh the data is, at a glance.

---

**Runs on your own server** (three small containers). Open source, MIT licence.
**Try it now, no install:** [dylan7474.github.io/CyberView/?demo](https://dylan7474.github.io/CyberView/?demo)

*More detail: [README](../README.md).*
