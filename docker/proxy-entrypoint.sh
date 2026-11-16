#!/bin/sh
# Use /certs/portal.crt + portal.key if present (put your own there to replace the self-signed one);
# otherwise make a self-signed pair valid for 10 years, naming this host and any extra names/IPs in CERT_NAMES.
set -e
C=/certs
if [ ! -s "$C/portal.crt" ] || [ ! -s "$C/portal.key" ]; then
  CN="${CERT_HOST:-portal.local}"
  SAN="DNS:${CN},DNS:localhost,IP:127.0.0.1"
  for n in $(echo "${CERT_NAMES:-}" | tr ',' ' '); do
    case "$n" in
      *[!0-9.]*) SAN="$SAN,DNS:$n" ;;
      *) if echo "$n" | grep -Eq '^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'; then SAN="$SAN,IP:$n"
         else echo "[proxy] WARNING: '$n' in CERT_NAMES is not a valid IP address, ignored. Fix it with: ./deploy.sh --cert-names ..." >&2; fi ;;
    esac
  done
  echo "[proxy] making a self-signed certificate for $SAN"
  umask 077
  openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
    -keyout "$C/portal.key" -out "$C/portal.crt" -subj "/O=Governance portal/CN=$CN" -addext "subjectAltName=$SAN"
  chmod 644 "$C/portal.crt"
fi
P=''; [ "${HTTPS_PUBLIC_PORT:-443}" = 443 ] || P=":${HTTPS_PUBLIC_PORT}"
sed -i "s|__PORT__|$P|" /etc/nginx/nginx.conf
exec nginx -g 'daemon off;'
