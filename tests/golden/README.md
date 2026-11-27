# Golden-number tests

The safety net for moving CyberView's data into proper database tables (stages 1–5). The rule is simple:
**for the same data, every page shows the same numbers before and after a change.** These tests record those
numbers once and fail when any of them moves.

## What is checked

| Run | What it does |
|---|---|
| `golden.py check` | Loads the fixture into a headless browser (demo mode, no server), opens the classic site and the new site, and reads **1,061 numbers** through the app's own code: register counts by team, tier, exposure and service; the Review Queue; findings, QIDs, KEV and EPSS; for every team P1–P4, tiers, overdue, backlog, exploited, the first 15 fixes and machines in order, fix families, the Patch Plan buckets; the Status page per team; Not seen; tasks; risk acceptances; on the new site, every priority model for every team (P1–P4, overdue, rows, the top 10, who fixes it), the step 2 gaps, Seen by and the trend. Compared with `expected/pages-demo.json`. |
| `golden.py server URL` | Replaces **all** data on a throwaway server with the fixture (as a backup restore does), then checks the API contract: `/api/state` gives every collection back unchanged, `/api/vuln/detections` and `/api/vuln/qids` give every finding and QID back unchanged, a whole-register save is stored with its revision up by one and appears in the history, and a save from an out-of-date copy is refused (409). Then both sites, signed in, against `expected/pages-server.json` (924 numbers; no Automox and no EPSS on a test server, so they differ from the demo's). |
| `../run_all.sh` | Everything: the browser check, a throwaway stack (`docker compose -p cvtest`), `tests/test_api.py`, the server check, then the stack removed. |

Every run freezes the clock at **27 Nov 2026 12:00 UTC** and answers the outside world (FIRST EPSS, the CISA KEV list,
endoflife.date) from `fixture/net.json`; anything else outside is refused. So the same code always gives the same numbers.

## Files

- `fixture/estate.json`: the ACME demo built at the frozen time: its stored collections, 766 findings and 42 QIDs. Made-up data.
- `fixture/net.json`: the recorded outside answers (the KEV list trimmed to the fixture's CVEs).
- `expected/*.json`: the numbers. **Only update them on purpose** (`--update`), when a change is meant to move numbers, and say so in the commit.
- `probe.js`: what is read from the pages (`goldenClassic()`, `goldenNew()`). Add numbers here when a page gains something worth protecting.
- `browser.py`: the small headless-Chromium driver (frozen clock, record and replay).
- `loader.html`: puts the fixture into the browser's demo storage.

## Commands

```
python3 tests/golden/golden.py check                    # no server, ~1 minute
tests/run_all.sh                                        # everything, ~5 minutes (docker)
python3 tests/golden/golden.py check --update           # accept new numbers (a deliberate change)
python3 tests/golden/golden.py capture                  # rebuild the fixture from the demo (network needed); then --update both
```

Needs chromium (or google-chrome) and Python's `websockets` (Debian: `python3-websockets`). Never point
`golden.py server` at the live portal: it replaces all its data. `run_all.sh` refuses to run in a checkout that has a `.env`.
