#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ${EUID} -ne 0 || ${1:-} != --yes || $# -ne 1 ]]; then
  echo "usage: sudo reset-lab.sh --yes" >&2
  echo "This removes the RelayForge database volume and rotates the flag." >&2
  exit 64
fi

project=/opt/relayforge/app
environment=/etc/relayforge/compose.env
systemctl stop relayforge-stack.service 2>/dev/null || true

while read -r unit _rest; do
  [[ $unit =~ ^relay-worker-[0-9a-f-]{36}\.service$ ]] || continue
  systemctl stop "$unit" 2>/dev/null || true
done < <(systemctl list-units --all --type=service --no-legend 'relay-worker-*.service')

systemctl stop relay-supervisor.service 2>/dev/null || true
/usr/bin/docker compose --project-directory "$project" --env-file "$environment" \
  down --volumes --remove-orphans --timeout 15
/usr/bin/python3 /opt/relayforge/runtime/cleanup_state.py
/opt/relayforge/runtime/init-challenge.sh --rotate
systemctl reset-failed 'relay-worker-*.service' 2>/dev/null || true
systemctl restart relay-backend.service relay-supervisor.service
systemctl restart relayforge-firewall.service
systemctl start relayforge-stack.service
/opt/relayforge/runtime/verify-hardening.sh
echo "RelayForge state reset; the root flag was rotated."
