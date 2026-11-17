# CyberView

**Stop drowning in findings. Start fixing what matters.**

CyberView turns your scanner output into a short, ranked to-do list, team by team.

## Feed it

- **Qualys:** every finding, pulled read-only from the API each morning, or a CSV export.
- **Automox:** agents, failing policies and waiting patches, read-only.
- **End-of-life dates:** from endoflife.date, plus your own extended-support dates.
- **Your people:** who owns each machine, how critical it is (Tier 1–3) and whether it faces the Internet, set once in the Asset Register. New machines arrive in a Review Queue with an owner already suggested.

## It joins the dots

- One machine, one record: Qualys, Automox and the register are matched by asset ID, name or IP. Where Qualys and Automox disagree about a machine's operating system, it lands in the Review Queue to settle.
- Every finding gets a **priority (P1–P4)** from how dangerous it is and how critical the machine is, with Internet-facing machines one step more urgent. Then a **due date**.
- One settings page, **Organisation setup**: teams, tiers, name matching and the status rules. Choose a built-in rule set: **Standard**, or **UK** (NCSC and Cyber Essentials deadlines, 5 days for Internet-facing).
- Tasks and accepted risks are tracked against the same data, and each morning's sync ticks fixes off automatically.

## What you get

- **Simple view** (the default): just the Dashboard, Patch Plan, Team Risk Report and End of Life Report. **Advanced** opens every page and setting.
- **Patch Plan:** every open finding set against Automox: what's patched, what Automox will patch in the next 7 days, what's blocked, and the gap that needs manual remediation, with machine lists for Ansible.
- **Vuln Management:** *Machines to fix first* and *Fixes that clear the most*, with one-click machine lists ready for Ansible.
- **Status:** one headline per team (On track / Slipping / Behind), with trend charts.
- **Team Risk Report:** a print-ready report per team: its status, the machines and fixes to do first, its Patch Plan, data gaps and recommended actions.
- **End of Life · Patch Coverage · Remediation:** what to upgrade, what isn't being patched, and who is fixing what by when.
- **Dashboard:** every team's status, this week's Patch Plan, end-of-life machines and how fresh the data is, at a glance.

---

**Runs on your own server** (three small containers). Open source, MIT licence.
**Try it now, no install:** [dylan7474.github.io/CyberView/?demo](https://dylan7474.github.io/CyberView/?demo)

*More detail: [README](../README.md).*
