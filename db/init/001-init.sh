#!/bin/sh
set -eu
umask 077

if [ "$POSTGRES_DB" != "relayforge" ]; then
  echo "POSTGRES_DB must be relayforge" >&2
  exit 1
fi
if [ -z "$RELAY_WEB_DB_PASSWORD" ] ||
   [ -z "$RELAY_ACCESS_DB_PASSWORD" ] ||
   [ -z "$RELAY_DISPATCH_DB_PASSWORD" ] ||
   [ -z "$RELAY_ENDPOINT_HOST" ] ||
   [ -z "$RELAY_ENDPOINT_PORT" ]; then
  echo "RelayForge database passwords and endpoint must be non-empty" >&2
  exit 1
fi

psql --no-password --set=ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set=web_pw="$RELAY_WEB_DB_PASSWORD" \
  --set=access_pw="$RELAY_ACCESS_DB_PASSWORD" \
  --set=dispatch_pw="$RELAY_DISPATCH_DB_PASSWORD" \
  --set=target_host="$RELAY_ENDPOINT_HOST" \
  --set=target_port="$RELAY_ENDPOINT_PORT" \
  --file=/docker-entrypoint-initdb.d/002-schema.sql.in
