#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi
exec /usr/bin/python3 /opt/relayforge/runtime/firewall.py \
  --config /etc/relayforge/firewall.env
