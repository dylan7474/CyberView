#!/usr/bin/env bash
# CyberView: build and run the whole solution (web app + MariaDB) as containers.
#
#   ./deploy.sh                      build and (re)start; makes a database backup first if one is running
#   ./deploy.sh --listen 127.0.0.1   restrict to this machine (default: all addresses)
#   ./deploy.sh --port 8443          change the HTTPS port (default: 443; plain HTTP on 80 redirects to it)
#   ./deploy.sh --http-port 8080     change the redirect port (default: 80)
#   ./deploy.sh --cert-names a,b     extra host names / IPs for the self-signed certificate (then delete ./certs to remake it)
#   ./deploy.sh --install-docker     Debian only: install docker.io + compose from Debian's repo first
#   ./deploy.sh status | logs        show state / follow logs
#   ./deploy.sh backup               dump the database to ./backups/
#   ./deploy.sh restore FILE [--yes] load a dump made by "backup"
#   ./deploy.sh users list | add NAME [--role viewer|editor|admin] | passwd NAME | role NAME ROLE | disable|enable|unlock|remove NAME
#   ./deploy.sh stop                 stop the containers (data kept)
#   ./deploy.sh automox              Automox patch data (read-only): show the setting
#   ./deploy.sh automox key          store the API key in .env (asked for, not echoed), then restart the app
#   ./deploy.sh automox org ID       choose the organisation (only needed when the key sees several)
#   ./deploy.sh automox hours N      sync on its own every N hours (0 = only when someone presses Sync)
#   ./deploy.sh automox test         check the key from the server: organisations, one page of devices and patches
#   ./deploy.sh automox off          remove the key
#   ./deploy.sh qualys               Qualys API sync (read-only, replaces the capped CSV export): show the settings
#   ./deploy.sh qualys url URL       your platform's API server, e.g. https://qualysapi.qg1.apps.qualys.co.uk
#                                    (Qualys: Help > About lists it; the gateway is worked out from it)
#   ./deploy.sh qualys user          store the Qualys user name (asked for)
#   ./deploy.sh qualys pass          store the password (asked for, not shown; kept encoded in .env, readable by root only)
#   ./deploy.sh qualys tag "NAME"    only hosts with this Qualys tag (e.g. "My Team");  qualys tag ""  = every host
#   ./deploy.sh qualys hour H        sync once a day at H:00 UTC (0-23);  qualys hour off  = only when someone presses Sync
#   ./deploy.sh qualys test          check the login and reach from the server (a few small read-only calls)
#   ./deploy.sh qualys watch         follow the running (or next) sync step by step; Ctrl+C to stop watching
#   ./deploy.sh qualys unblock       allow syncs again after Qualys refused the login (when the password was right)
#   ./deploy.sh qualys off           remove the user name and password
#   ./deploy.sh clean                remove leftovers of older deployments (other folders, old versions, unused images). Data kept.
#   ./deploy.sh clean --purge [--yes] ALSO delete this portal's database and containers: everything. Asks you to type a phrase.
#                                    (every deploy already does the safe part of "clean" first)
#
# Settings live in .env (created on the first run with a random database password). Data lives in Docker volumes.
set -euo pipefail
cd "$(dirname "$0")"

say() { printf '\033[1m[deploy]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[deploy] %s\033[0m\n' "$*" >&2; exit 1; }

INSTALL_DOCKER=0; NO_BACKUP=0; LISTEN=""; PORT_ARG=""; HTTP_ARG=""; NAMES_ARG=""; CMD="deploy"; ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --install-docker) INSTALL_DOCKER=1 ;;
    --no-backup) NO_BACKUP=1 ;;
    --listen) LISTEN="${2:?--listen needs an address}"; shift ;;
    --port) PORT_ARG="${2:?--port needs a number}"; shift ;;
    --http-port) HTTP_ARG="${2:?--http-port needs a number}"; shift ;;
    --cert-names) NAMES_ARG="${2:?--cert-names needs names or IPs, comma separated}"; shift ;;
    deploy|status|logs|backup|restore|users|stop|clean|automox|qualys) CMD="$1" ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
    *) ARGS+=("$1") ;;
  esac
  shift
done

# --- docker -----------------------------------------------------------------
SUDO=""
install_docker() {
  [ -r /etc/debian_version ] || die "--install-docker only knows Debian. Install Docker yourself, then run this again."
  say "installing docker.io and docker-compose from the Debian repository"
  if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi
  $SUDO apt-get update
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose
  $SUDO systemctl enable --now docker
}
command -v docker >/dev/null 2>&1 || { [ "$INSTALL_DOCKER" = 1 ] && install_docker || die "Docker is not installed. Run: ./deploy.sh --install-docker   (Debian) or install it yourself."; }
if ! docker info >/dev/null 2>&1; then
  if sudo -n docker info >/dev/null 2>&1 || { [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null && sudo docker info >/dev/null 2>&1; }; then SUDO="sudo"
  else die "Cannot talk to Docker. Start it, or add yourself to the docker group, or run as root."; fi
fi
if $SUDO docker compose version >/dev/null 2>&1; then DC="$SUDO docker compose"
elif command -v docker-compose >/dev/null 2>&1; then DC="$SUDO docker-compose"
else
  [ "$INSTALL_DOCKER" = 1 ] && install_docker
  DC="$SUDO docker-compose"; command -v docker-compose >/dev/null 2>&1 || die "Docker Compose is missing. Run: ./deploy.sh --install-docker"
fi

# --- settings ---------------------------------------------------------------
if [ ! -f .env ]; then
  say "creating .env with a random database password"
  umask 077
  printf 'DB_PASSWORD=%s\nBIND_ADDRESS=0.0.0.0\nHTTPS_PORT=443\nHTTP_PORT=80\nCERT_HOST=%s\n' "$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')" "$(hostname -f 2>/dev/null || hostname)" > .env
fi
setenv() { grep -q "^$1=" .env && sed -i "s|^$1=.*|$1=$2|" .env || echo "$1=$2" >> .env; }
[ -n "$LISTEN" ] && setenv BIND_ADDRESS "$LISTEN"
[ -n "$PORT_ARG" ] && setenv HTTPS_PORT "$PORT_ARG"
[ -n "$HTTP_ARG" ] && setenv HTTP_PORT "$HTTP_ARG"
if [ -n "$NAMES_ARG" ]; then
  for n in $(echo "$NAMES_ARG" | tr ',' ' '); do
    if [[ "$n" =~ ^[0-9.]+$ ]] && ! [[ "$n" =~ ^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
      die "--cert-names: '$n' is not a valid IP address (four numbers 0-255 separated by dots, e.g. 203.0.113.10). Check for a missing or extra dot."
    fi
  done
  setenv CERT_NAMES "$NAMES_ARG"
fi
# older .env files (before v3.2) had PORT=; carry it over as the HTTP redirect port, HTTPS defaults to 443
if grep -q '^PORT=' .env; then grep -q '^HTTPS_PORT=' .env || echo "HTTPS_PORT=443" >> .env; grep -q '^HTTP_PORT=' .env || echo "HTTP_PORT=80" >> .env; sed -i '/^PORT=/d' .env; fi
grep -q '^CERT_HOST=' .env || echo "CERT_HOST=$(hostname -f 2>/dev/null || hostname)" >> .env
mkdir -p certs
# shellcheck disable=SC1091
set -a; . ./.env; set +a

db_running() { [ -n "$($DC ps -q db 2>/dev/null)" ] && [ "$($DC ps --status running -q db 2>/dev/null | wc -l)" -gt 0 ]; }

do_backup() {
  mkdir -p backups
  local f="backups/qualys-$(date +%Y%m%d-%H%M%S).sql.gz"
  $DC exec -T db mariadb-dump --single-transaction --routines qualys | gzip > "$f"
  [ -s "$f" ] && gzip -t "$f" || { rm -f "$f"; die "backup failed"; }
  say "backup written: $f ($(du -h "$f" | cut -f1))"
  ls -1t backups/qualys-*.sql.gz 2>/dev/null | tail -n +15 | xargs -r rm -f   # keep the newest 14
}

# --- leftovers of older deployments ------------------------------------------
PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$PWD" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')}"
dk() { $SUDO docker "$@"; }

# Containers of this portal that belong to ANOTHER folder/project (a previous clone, a renamed folder, an older version).
# They keep ports 80/443 and the same image names busy. Matches the portal's image names, or a compose folder named like CyberView (or QualysReporting, its earlier name).
legacy_containers() {
  dk ps -a --format '{{.ID}}|{{.Image}}|{{.Label "com.docker.compose.project"}}|{{.Names}}|{{.Label "com.docker.compose.project.working_dir"}}' 2>/dev/null \
    | awk -F'|' -v p="$PROJECT" '$3 != p && ($2 ~ /^governance-portal-(db|app|proxy)(:|$)/ || tolower($5) ~ /qualysreporting|cyberview/) {print $1"|"$4"|"$3}'
}

clean_legacy() {
  local found; found="$(legacy_containers)"
  if [ -n "$found" ]; then
    say "removing containers left by an older deployment (their data volumes are kept):"
    echo "$found" | while IFS='|' read -r id name proj; do printf '         %s (project %s)\n' "$name" "${proj:-none}"; dk rm -f "$id" >/dev/null; done
  fi
  # containers of THIS project that are not up (crashed or half-started) are recreated by "up", but exited ones from old runs are removed here
  dk ps -a --filter "label=com.docker.compose.project=$PROJECT" --filter status=exited --format '{{.ID}}' | xargs -r $SUDO docker rm >/dev/null 2>&1 || true
}

check_ports() {
  # something other than this portal already using 80/443 would make "up" fail with an obscure message
  local mine; mine="$($DC ps -q proxy 2>/dev/null | wc -l)"
  [ "$mine" -gt 0 ] && return 0
  for pt in "${HTTPS_PORT:-443}" "${HTTP_PORT:-80}"; do
    if command -v ss >/dev/null 2>&1 && ss -ltn "sport = :$pt" 2>/dev/null | grep -q LISTEN; then
      die "port $pt is already in use by something else on this host (see: sudo ss -ltnp 'sport = :$pt'). Stop it, or choose other ports with --port N --http-port N."
    fi
  done
}

do_purge() {
  if [[ " ${ARGS[*]} " != *" --yes "* ]]; then
    say "THIS DELETES this folder's portal database (all data and users) and the portal's containers, including those of older copies. Other copies' databases are only listed."
    read -r -p 'Type  delete everything  to go on: ' a; [ "$a" = "delete everything" ] || die "cancelled, nothing deleted"
  fi
  $DC down -v --remove-orphans >/dev/null 2>&1 || true
  legacy_containers | cut -d'|' -f1 | xargs -r $SUDO docker rm -f >/dev/null 2>&1 || true
  # data volume of THIS project only; older copies' volumes are listed, never deleted automatically
  dk volume ls -q --filter label=com.docker.compose.volume=dbdata --format '{{.Name}}|{{.Label "com.docker.compose.project"}}' 2>/dev/null \
    | awk -F'|' -v p="$PROJECT" '$2 == p {print $1}' | xargs -r $SUDO docker volume rm -f >/dev/null 2>&1 || true
  others="$(dk volume ls -q --filter label=com.docker.compose.volume=dbdata --format '{{.Name}}|{{.Label "com.docker.compose.project"}}' 2>/dev/null | awk -F'|' -v p="$PROJECT" '$2 != p && tolower($2) ~ /qualys|governance|portal|^qr/ {print $1}')"
  dk rmi -f governance-portal-db:latest governance-portal-app:latest governance-portal-proxy:latest >/dev/null 2>&1 || true
  [ -n "$others" ] && say "databases of OTHER copies are still there (delete one with: docker volume rm NAME): $(echo $others)"
  say "everything of the portal is deleted. ./certs and .env are kept: delete them yourself for a completely fresh start."
}

wait_healthy() {
  say "waiting for the app to come up"
  for _ in $(seq 1 60); do
    st=$($DC ps -q app 2>/dev/null | xargs -r $SUDO docker inspect -f '{{.State.Health.Status}}' 2>/dev/null || true)
    [ "$st" = "healthy" ] && return 0
    sleep 3
  done
  $DC logs --tail 40 app db || true
  die "the app did not become healthy; logs above"
}

case "$CMD" in
  deploy)
    if [ "$NO_BACKUP" = 0 ] && db_running; then say "backing up the database before the update"; do_backup; fi
    clean_legacy
    check_ports
    say "building images (needs to reach Debian's package mirrors the first time)"
    $DC build
    $DC up -d --remove-orphans
    wait_healthy
    H="${CERT_HOST:-$(hostname -f 2>/dev/null || hostname)}"; P=""; [ "${HTTPS_PORT:-443}" = "443" ] || P=":${HTTPS_PORT}"
    if [ "$BIND_ADDRESS" = "0.0.0.0" ]; then say "running: https://${H}${P}/  (port ${HTTP_PORT:-80} redirects to it)"
    else say "running: https://${BIND_ADDRESS}${P}/ (only that address; --listen 0.0.0.0 for all)"; fi
    if [ "$(openssl x509 -in certs/portal.crt -noout -issuer 2>/dev/null | sed 's/^issuer=//')" = "$(openssl x509 -in certs/portal.crt -noout -subject 2>/dev/null | sed 's/^subject=//')" ] && [ -s certs/portal.crt ]; then
      say "the certificate is SELF-SIGNED: browsers warn once per person. It covers ${CERT_HOST:-?} and localhost; add other names/IPs with --cert-names a,b after deleting ./certs, or put your own portal.crt + portal.key in ./certs."
    fi
    if $DC exec -T app python3 /app/users.py list 2>/dev/null | grep -q 'no users'; then
      say "there are NO users yet, so the portal is OPEN to everyone as administrator."
      if [ -t 0 ]; then
        read -r -p "Create the first administrator now? [Y/n] " a
        if [ "${a:-y}" != n ] && [ "${a:-y}" != N ]; then
          read -r -p "User name: " u
          $DC exec -it app python3 /app/users.py add "$u" --role admin || say "not created; run: ./deploy.sh users add NAME --role admin"
        fi
      else
        say "create one with: ./deploy.sh users add NAME --role admin   (or open the site and use Users)"
      fi
    fi
    ;;
  clean)
    if [[ " ${ARGS[*]} " == *" --purge "* ]]; then do_purge
    else
      clean_legacy
      dk image prune -f >/dev/null 2>&1 && say "unused (dangling) images from older builds removed"
      say "clean: done. Nothing of your data was touched. (Use  clean --purge  to delete the database too.)"
    fi
    ;;
  status) $DC ps ;;
  logs) $DC logs -f --tail 100 ;;
  stop) $DC stop ;;
  backup) db_running || die "the database is not running"; do_backup ;;
  restore)
    f="${ARGS[0]:-}"; [ -f "$f" ] || die "usage: ./deploy.sh restore backups/FILE.sql.gz [--yes]"
    db_running || die "the database is not running (run ./deploy.sh first)"
    if [[ " ${ARGS[*]} " != *" --yes "* ]]; then read -r -p "This REPLACES all portal data with $f. Type yes: " a; [ "$a" = yes ] || die "cancelled"; fi
    say "taking a safety backup first"; do_backup
    gzip -dc "$f" | $DC exec -T db mariadb qualys
    $DC restart app
    wait_healthy
    say "restored from $f"
    ;;
  automox)
    app_restart() { if [ -n "$($DC ps -q app 2>/dev/null)" ]; then say "restarting the app with the new setting"; $DC up -d app >/dev/null; wait_healthy; else say "saved; it takes effect on the next ./deploy.sh"; fi; }
    case "${ARGS[0]:-show}" in
      show)
        if grep -q '^AUTOMOX_API_KEY=.' .env; then say "Automox: key set (not shown)"; else say "Automox: no key (./deploy.sh automox key)"; fi
        say "organisation: ${AUTOMOX_ORG_ID:-automatic}   scheduled sync: every ${AUTOMOX_SYNC_HOURS:-0} hours (0 = off)" ;;
      key)
        [ -t 0 ] || die "run this in a terminal: it asks for the key"
        read -r -s -p "Automox API key (not shown): " k; echo
        [ -n "$k" ] || die "no key entered"
        [[ "$k" =~ ^[A-Za-z0-9._~+/=-]+$ ]] || die "that does not look like an API key (unexpected characters); nothing saved"
        setenv AUTOMOX_API_KEY "$k"; chmod 600 .env; unset k
        say "key saved in .env (readable by root only)"; app_restart
        say "check it with: ./deploy.sh automox test" ;;
      org)
        o="${ARGS[1]:-}"; [[ "$o" =~ ^[0-9]*$ ]] || die "usage: ./deploy.sh automox org ID   (a number; empty = automatic)"
        setenv AUTOMOX_ORG_ID "$o"; app_restart ;;
      hours)
        h="${ARGS[1]:-}"; [[ "$h" =~ ^[0-9]+$ ]] || die "usage: ./deploy.sh automox hours N   (0 = off)"
        setenv AUTOMOX_SYNC_HOURS "$h"; app_restart ;;
      test) $DC exec -T app python3 /app/automox.py test ;;
      off) sed -i '/^AUTOMOX_API_KEY=/d' .env; say "key removed from .env"; app_restart ;;
      *) die "usage: ./deploy.sh automox [show|key|org ID|hours N|test|off]" ;;
    esac
    ;;
  qualys)
    app_restart() { if [ -n "$($DC ps -q app 2>/dev/null)" ]; then say "restarting the app with the new setting"; $DC up -d app >/dev/null; wait_healthy; else say "saved; it takes effect on the next ./deploy.sh"; fi; }
    b64() { printf '%s' "$1" | base64 -w0; }
    unb64() { printf '%s' "$1" | base64 -d 2>/dev/null; }
    case "${ARGS[0]:-show}" in
      show)
        say "Qualys API: ${QUALYS_API_URL:-not set (./deploy.sh qualys url URL)}"
        say "user: ${QUALYS_USERNAME:-not set}   password: $(grep -q '^QUALYS_PASSWORD_B64=.' .env && echo 'set (not shown)' || echo 'not set')"
        t="$(unb64 "${QUALYS_SCOPE_TAG_B64:-}")"
        say "scope: ${t:-every host}   daily sync: $([ -n "${QUALYS_SYNC_HOUR:-}" ] && echo "${QUALYS_SYNC_HOUR}:00 UTC" || echo off)" ;;
      url)
        u="${ARGS[1]:-}"; [[ "$u" =~ ^https://[A-Za-z0-9.-]+/?$ ]] || die "usage: ./deploy.sh qualys url https://qualysapi.YOUR-PLATFORM   (Qualys: Help > About)"
        setenv QUALYS_API_URL "${u%/}"; app_restart ;;
      user)
        [ -t 0 ] || die "run this in a terminal: it asks for the user name"
        read -r -p "Qualys user name: " u
        [[ "$u" =~ ^[A-Za-z0-9._@-]+$ ]] || die "that does not look like a Qualys user name; nothing saved"
        setenv QUALYS_USERNAME "$u"; app_restart ;;
      pass)
        [ -t 0 ] || die "run this in a terminal: it asks for the password"
        read -r -s -p "Qualys password (not shown): " p; echo
        [ -n "$p" ] || die "no password entered"
        setenv QUALYS_PASSWORD_B64 "$(b64 "$p")"; chmod 600 .env; unset p
        say "password saved in .env (encoded, readable by root only)"; app_restart
        say "check it with: ./deploy.sh qualys test" ;;
      tag)
        [ ${#ARGS[@]} -ge 2 ] || die 'usage: ./deploy.sh qualys tag "TAG NAME"   (qualys tag "" = every host)'
        setenv QUALYS_SCOPE_TAG_B64 "$(b64 "${ARGS[1]}")"; say "scope: ${ARGS[1]:-every host}"; app_restart ;;
      hour)
        h="${ARGS[1]:-}"
        if [ "$h" = off ]; then setenv QUALYS_SYNC_HOUR ""; else [[ "$h" =~ ^([0-9]|1[0-9]|2[0-3])$ ]] || die "usage: ./deploy.sh qualys hour 0-23 | off"; setenv QUALYS_SYNC_HOUR "$h"; fi
        app_restart ;;
      test) $DC exec -T app python3 /app/qualys.py test ;;
      watch) if [ -t 1 ]; then $DC exec app python3 -u /app/qualys.py watch; else $DC exec -T app python3 -u /app/qualys.py watch; fi ;;
      unblock) $DC exec -T app python3 /app/qualys.py unblock ;;
      off) sed -i '/^QUALYS_USERNAME=/d; /^QUALYS_PASSWORD_B64=/d' .env; say "user name and password removed from .env"; app_restart ;;
      *) die "usage: ./deploy.sh qualys [show|url URL|user|pass|tag NAME|hour H|test|watch|unblock|off]" ;;
    esac
    ;;
  users)
    [ ${#ARGS[@]} -gt 0 ] || ARGS=(list)
    $DC exec -it app python3 /app/users.py "${ARGS[@]}"
    ;;
esac
