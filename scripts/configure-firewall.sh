#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ${EUID} -ne 0 || $# -ne 2 ]]; then
  echo "usage: sudo configure-firewall.sh PLAYER_CIDR PUBLIC_IFACE" >&2
  exit 64
fi
player_cidr=$1
public_interface=$2
compose_environment=/etc/relayforge/compose.env
if [[ -L $compose_environment || ! -f $compose_environment || \
      $(stat -c '%U:%G:%a' "$compose_environment") != root:root:600 ]]; then
  echo "Safe compose endpoint configuration is unavailable." >&2
  exit 1
fi
endpoint_host=$(sed -n 's/^RELAY_ENDPOINT_HOST=//p' "$compose_environment")
endpoint_port=$(sed -n 's/^RELAY_ENDPOINT_PORT=//p' "$compose_environment")
/usr/bin/python3 - "$endpoint_host" "$endpoint_port" <<'PY'
import ipaddress, sys

address = ipaddress.IPv4Address(sys.argv[1])
if str(address) != sys.argv[1] or address.is_unspecified or address.is_multicast or int(address) == 0xFFFFFFFF:
    raise SystemExit("endpoint host is not a canonical usable IPv4 address")
port = int(sys.argv[2])
if str(port) != sys.argv[2] or not 1 <= port <= 65535:
    raise SystemExit("endpoint port is not canonical or is out of range")
PY
/usr/bin/python3 - "$player_cidr" <<'PY'
import ipaddress, sys
for item in sys.argv[1:]:
    network = ipaddress.IPv4Network(item, strict=True)
    if str(network) != item:
        raise SystemExit(f"CIDR is not canonical: {item}")
PY
[[ $public_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ && -d /sys/class/net/$public_interface ]] || {
  echo "Invalid public interface." >&2
  exit 1
}

temporary=$(mktemp /etc/relayforge/.firewall.env.XXXXXX)
trap 'rm -f -- "$temporary"' EXIT
{
  printf 'PLAYER_CIDR=%s\n' "$player_cidr"
  printf 'PUBLIC_IFACE=%s\n' "$public_interface"
  printf 'ENDPOINT_HOST=%s\n' "$endpoint_host"
  printf 'ENDPOINT_PORT=%s\n' "$endpoint_port"
  echo 'FIREWALL_DEFERRED=0'
} >"$temporary"
install -o root -g root -m 0600 "$temporary" /etc/relayforge/firewall.env
trap - EXIT

if [[ -f /etc/relayforge/install.state ]]; then
  sed -i 's/^FIREWALL_DEFERRED=.*/FIREWALL_DEFERRED=0/' /etc/relayforge/install.state
fi
systemctl daemon-reload
systemctl enable relay-backend.service relay-supervisor.service \
  relayforge-firewall.service relayforge-stack.service
systemctl restart relay-backend.service relay-supervisor.service
systemctl restart relayforge-firewall.service
systemctl restart relayforge-stack.service
/opt/relayforge/runtime/verify-hardening.sh
