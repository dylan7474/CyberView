#!/usr/bin/env bash
# Every check, in order, the way each release is tested (developer machine only, NOT on the live server):
#   1. golden numbers, no server (both sites in a headless browser, frozen clock, replayed network)
#   2. a throwaway server stack (docker compose project "cvtest", ports 18943/18980 on 127.0.0.1, its own volumes)
#   3. the API tests (tests/test_api.py) on it
#   4. golden numbers on the server: the fixture loaded, the API round trip, both sites signed in
#   5. the stack and its volumes removed again
# Needs: docker compose, chromium (or google-chrome), python3 with websockets (Debian: python3-websockets).
#   tests/run_all.sh            run everything
#   tests/run_all.sh --no-server   only step 1
set -u
cd "$(dirname "$0")/.."
if [ -f .env ]; then
  echo "This checkout has a .env: it looks like a real deployment. Run the tests in a separate copy (git worktree add ../cv-test)." >&2
  exit 2
fi
fail=0
python3 tests/golden/golden.py check || fail=1
[ "${1:-}" = "--no-server" ] && exit $fail

ENVF=$(mktemp)
printf 'DB_PASSWORD=%s\nBIND_ADDRESS=127.0.0.1\nHTTPS_PORT=18943\nHTTP_PORT=18980\nCERT_HOST=localhost\nEOL_SYNC_HOURS=0\nREDHAT_SYNC_HOURS=0\nEPSS_SYNC_HOURS=0\nAUTOMOX_SYNC_HOURS=0\nKEV_SYNC_HOURS=0\n' "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$ENVF"
cleanup() {
  docker compose --env-file "$ENVF" -p cvtest down -v --rmi local >/dev/null 2>&1
  docker run --rm -v "$PWD":/w alpine sh -c 'rm -rf /w/certs' >/dev/null 2>&1 || true     # the proxy writes its self-signed cert as root
  rm -f "$ENVF"
}
trap cleanup EXIT
echo "Starting a throwaway stack (cvtest)…"
docker compose --env-file "$ENVF" -p cvtest up -d --build >/dev/null 2>&1 || { echo "the stack did not start" >&2; exit 1; }
for _ in $(seq 1 60); do curl -sk https://127.0.0.1:18943/api/health | grep -q '"ok":true' && break; sleep 3; done
echo "API tests:"
python3 tests/test_api.py https://127.0.0.1:18943 > /tmp/cv-api-tests.txt 2>&1
if tail -1 /tmp/cv-api-tests.txt | grep -q "all passed"; then echo "  PASS $(grep -c '^PASS' /tmp/cv-api-tests.txt) API tests"; else grep -v '^PASS' /tmp/cv-api-tests.txt | tail -20; fail=1; fi
# the API tests leave their own users and data behind: start the golden server run from an empty database
docker compose --env-file "$ENVF" -p cvtest down -v >/dev/null 2>&1
docker compose --env-file "$ENVF" -p cvtest up -d >/dev/null 2>&1
for _ in $(seq 1 60); do curl -sk https://127.0.0.1:18943/api/health | grep -q '"ok":true' && break; sleep 3; done
python3 tests/golden/golden.py server https://127.0.0.1:18943 || fail=1
[ $fail = 0 ] && echo "EVERYTHING PASSED" || echo "SOMETHING FAILED"
exit $fail
