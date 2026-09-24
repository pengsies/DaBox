#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
umask 077

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$root"

command -v docker >/dev/null
command -v openssl >/dev/null
docker compose version >/dev/null

secret_dir=$(mktemp -d /tmp/relayforge-container-test.XXXXXX)
compose=(
  docker compose
  -f "$root/compose.yaml"
  -f "$root/tests/compose.integration.yaml"
  --env-file "$root/.env.example"
)
dispatch_compose=(
  docker compose
  -f "$root/compose.yaml"
  -f "$root/tests/compose.integration.yaml"
  -f "$root/tests/compose.dispatcher.yaml"
  --env-file "$root/.env.example"
)
export RF_TEST_SECRETS=$secret_dir

cleanup() {
  "${dispatch_compose[@]}" down --volumes --remove-orphans --timeout 15 >/dev/null 2>&1 || true
  rm -rf -- "$secret_dir"
}
trap cleanup EXIT INT TERM

install -d -m 0700 "$secret_dir/tls"
openssl genpkey -algorithm ED25519 -out "$secret_dir/job-signing.pem" >/dev/null 2>&1
openssl pkey -in "$secret_dir/job-signing.pem" -pubout \
  -out "$secret_dir/job-signing.pub" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
  -subj '/CN=localhost' -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout "$secret_dir/tls/server.key" -out "$secret_dir/tls/server.crt" \
  >/dev/null 2>&1
# The enclosing directory remains 0700. Files are world-readable only inside
# this disposable fixture because container IDs do not match the host caller;
# production installation uses root/group ownership and 0440/0400 modes.
chmod 0444 "$secret_dir/job-signing.pem" "$secret_dir/job-signing.pub" \
  "$secret_dir/tls/server.key" "$secret_dir/tls/server.crt"

"${dispatch_compose[@]}" down --volumes --remove-orphans --timeout 15
"${compose[@]}" up --detach --build --wait postgres access
python3 tests/dispatcher_integration.py --secrets "$secret_dir"

"${compose[@]}" down --volumes --remove-orphans --timeout 15
"${compose[@]}" up --detach --build --wait postgres access web edge
python3 tests/container_integration.py --secrets "$secret_dir"
python3 tests/container_security.py --secrets "$secret_dir"

echo "PASS: disposable container integration suite"
