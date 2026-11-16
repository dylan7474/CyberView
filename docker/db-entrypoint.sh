#!/bin/bash
# First start: create the data directory, the database and the portal's own user. Later starts: just run.
set -euo pipefail
: "${DB_NAME:?}" "${DB_USER:?}" "${DB_PASSWORD:?}"
DATADIR=/var/lib/mysql
mkdir -p /run/mysqld && chown mysql:mysql /run/mysqld "$DATADIR"
INIT=()
if [ ! -d "$DATADIR/mysql" ]; then
  echo "[db] first start: initialising $DATADIR"
  mariadb-install-db --user=mysql --datadir="$DATADIR" --skip-test-db --auth-root-authentication-method=socket >/dev/null
  SQL=/run/mysqld/init.sql
  umask 077
  cat > "$SQL" <<SQLEOF
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASSWORD}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'%';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQLEOF
  chown mysql "$SQL"
  INIT=(--init-file="$SQL")
fi
exec mariadbd --user=mysql --datadir="$DATADIR" "${INIT[@]}"
