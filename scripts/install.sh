#!/usr/bin/env bash
set -euo pipefail
umask 077

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
player_cidr=${PLAYER_CIDR:-0.0.0.0/0}
public_interface=${PUBLIC_IFACE:-}
admin_user=${ADMIN_USER:-${SUDO_USER:-}}
endpoint_host=${RELAY_ENDPOINT_HOST:-127.0.0.1}
endpoint_port=${RELAY_ENDPOINT_PORT:-19001}
defer_firewall=0
defer_ssh=0

usage() {
  cat >&2 <<'USAGE'
usage: sudo scripts/install.sh [options]
  --player-cidr CIDR      IPv4 network allowed to reach HTTPS/Workers
                          (default: 0.0.0.0/0, public IPv4)
  --public-interface IF   host interface facing those networks
  --admin-user USER       existing key-authenticated SSH administrator
  --endpoint-host IPV4    approved HTTP endpoint IPv4 (default: 127.0.0.1)
  --endpoint-port PORT    approved HTTP endpoint port (default: 19001)
  --defer-firewall        install/build but do not start the challenge
  --defer-ssh-hardening   leave SSH policy unchanged (verification will fail)

Values may instead be supplied as PLAYER_CIDR, PUBLIC_IFACE,
ADMIN_USER, RELAY_ENDPOINT_HOST, and RELAY_ENDPOINT_PORT environment variables.
USAGE
  exit 64
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --player-cidr) [[ $# -ge 2 ]] || usage; player_cidr=$2; shift 2 ;;
    --public-interface) [[ $# -ge 2 ]] || usage; public_interface=$2; shift 2 ;;
    --admin-user) [[ $# -ge 2 ]] || usage; admin_user=$2; shift 2 ;;
    --endpoint-host) [[ $# -ge 2 ]] || usage; endpoint_host=$2; shift 2 ;;
    --endpoint-port) [[ $# -ge 2 ]] || usage; endpoint_port=$2; shift 2 ;;
    --defer-firewall) defer_firewall=1; shift ;;
    --defer-ssh-hardening) defer_ssh=1; shift ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "Run the installer as root (normally with sudo)." >&2
  exit 1
fi
if [[ $(uname -m) != x86_64 ]]; then
  echo "RelayForge requires an AMD64 host." >&2
  exit 1
fi
os_id=$(sed -n 's/^ID=//p' /etc/os-release | head -n1 | tr -d '"')
os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | head -n1 | tr -d '"')
if [[ $os_id != ubuntu || $os_version != 24.04 ]]; then
  echo "RelayForge requires a patched Ubuntu Server 24.04.x LTS host." >&2
  exit 1
fi

if [[ $defer_firewall -eq 0 ]]; then
  [[ -n $public_interface ]] || usage
  /usr/bin/python3 - "$player_cidr" <<'PY'
import ipaddress, sys
for item in sys.argv[1:]:
    network = ipaddress.IPv4Network(item, strict=True)
    if str(network) != item:
        raise SystemExit(f"CIDR is not canonical: {item}")
PY
  [[ $public_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || { echo "Invalid public interface." >&2; exit 1; }
  [[ -d /sys/class/net/$public_interface ]] || { echo "Public interface does not exist." >&2; exit 1; }
  if [[ $player_cidr == 0.0.0.0/0 ]]; then
    echo "WARNING: HTTPS and Worker ports are open to every IPv4 source allowed by external firewalls." >&2
  fi
else
  player_cidr=127.0.0.1/32
  public_interface=lo
fi
/usr/bin/python3 - "$endpoint_host" "$endpoint_port" <<'PY'
import ipaddress, sys

address = ipaddress.IPv4Address(sys.argv[1])
if (
    str(address) != sys.argv[1]
    or address.is_unspecified
    or address.is_multicast
    or int(address) == 0xFFFFFFFF
):
    raise SystemExit("endpoint host must be a canonical unicast IPv4 address")
try:
    port = int(sys.argv[2])
except ValueError as exc:
    raise SystemExit("endpoint port must be an integer") from exc
if str(port) != sys.argv[2] or not 1 <= port <= 65535:
    raise SystemExit("endpoint port must be canonical and between 1 and 65535")
PY
if [[ $defer_ssh -eq 0 ]]; then
  [[ $admin_user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "An existing --admin-user is required." >&2; exit 1; }
fi

# PostgreSQL only runs the schema initializer for a new data volume. Refuse an
# older environment before packages, runtime files, or services are changed;
# silently adding endpoint variables would leave the persistent DB on the old
# schema and break the Access contract.
compose_environment=/etc/relayforge/compose.env
if [[ -L $compose_environment || ( -e $compose_environment && ! -f $compose_environment ) ]]; then
  echo "Unsafe compose environment file." >&2
  exit 1
fi
if [[ -e $compose_environment ]]; then
  if [[ $(stat -c '%U:%G:%a' "$compose_environment") != root:root:600 ]]; then
    echo "Unsafe compose environment file." >&2
    exit 1
  fi
  endpoint_host_entries=$(grep -c '^RELAY_ENDPOINT_HOST=' "$compose_environment" || true)
  endpoint_port_entries=$(grep -c '^RELAY_ENDPOINT_PORT=' "$compose_environment" || true)
  flask_secret_entries=$(grep -c '^FLASK_SECRET_KEY=' "$compose_environment" || true)
  if [[ $endpoint_host_entries -ne 1 || $endpoint_port_entries -ne 1 || $flask_secret_entries -ne 1 ]]; then
    echo "In-place upgrade from a pre-endpoint or pre-Flask deployment is unsupported." >&2
    echo "Back up and explicitly reset the database/environment on a disposable lab VM, then rerun." >&2
    exit 1
  fi
  recorded_endpoint_host=$(sed -n 's/^RELAY_ENDPOINT_HOST=//p' "$compose_environment")
  recorded_endpoint_port=$(sed -n 's/^RELAY_ENDPOINT_PORT=//p' "$compose_environment")
  if [[ $recorded_endpoint_host != "$endpoint_host" || $recorded_endpoint_port != "$endpoint_port" ]]; then
    echo "Endpoint differs from the recorded deployment; supply the original endpoint or redeploy explicitly." >&2
    exit 1
  fi
fi

for selected in control db web config host scripts worker; do
  if find "$project_dir/$selected" -type l -print -quit | grep -q .; then
    echo "Refusing a source tree containing symbolic links: $selected" >&2
    exit 1
  fi
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  binutils build-essential ca-certificates curl docker.io docker-compose-v2 iproute2 \
  iptables openssh-server openssl python3 python3-cryptography rsync

install -d -o root -g root -m 0755 /etc/docker
if [[ -e /etc/docker/daemon.json ]]; then
  if ! cmp -s "$project_dir/config/docker-daemon.json" /etc/docker/daemon.json; then
    echo "Existing /etc/docker/daemon.json differs; refusing to overwrite it." >&2
    exit 1
  fi
else
  install -o root -g root -m 0644 "$project_dir/config/docker-daemon.json" /etc/docker/daemon.json
fi
systemctl enable docker.service
systemctl restart docker.service
docker_info=$(docker info --format '{{json .SecurityOptions}}')
if [[ $docker_info == *userns* || $docker_info == *rootless* ]]; then
  echo "Docker user-namespace remapping/rootless mode is unsupported by this host-bound lab." >&2
  exit 1
fi

ensure_group() {
  local group_name=$1
  if ! getent group "$group_name" >/dev/null; then
    groupadd --system "$group_name"
  fi
  local members
  members=$(getent group "$group_name" | cut -d: -f4)
  if [[ -n $members ]]; then
    echo "Group $group_name has unexpected supplementary members: $members" >&2
    exit 1
  fi
}

ensure_user() {
  local user_name=$1
  local primary_group=$2
  if ! id "$user_name" >/dev/null 2>&1; then
    useradd --system --gid "$primary_group" --home-dir /nonexistent \
      --no-create-home --shell /usr/sbin/nologin "$user_name"
  fi
  local uid_value group_value home_value shell_value group_list
  uid_value=$(id -u "$user_name")
  group_value=$(id -gn "$user_name")
  home_value=$(getent passwd "$user_name" | cut -d: -f6)
  shell_value=$(getent passwd "$user_name" | cut -d: -f7)
  group_list=$(id -nG "$user_name")
  if [[ $uid_value -le 0 || $uid_value -ge 1000 || $group_value != "$primary_group" || \
        $home_value != /nonexistent || \
        $shell_value != /usr/sbin/nologin || $group_list != "$primary_group" ]]; then
    echo "Existing identity $user_name is incompatible or over-privileged." >&2
    exit 1
  fi
}

ensure_group relayforge-ipc
ensure_group relayforge-signing
ensure_group relay-backend
ensure_user relay relayforge-ipc
ensure_user relay-dispatch relayforge-ipc
ensure_user relay-backend relay-backend
for service_user in relay relay-dispatch relay-backend; do
  for forbidden_group in docker sudo adm shadow systemd-journal; do
    if id -nG "$service_user" | tr ' ' '\n' | grep -Fxq "$forbidden_group"; then
      echo "$service_user unexpectedly belongs to $forbidden_group." >&2
      exit 1
    fi
  done
done

install -d -o root -g root -m 0755 /opt/relayforge /opt/relayforge/app \
  /opt/relayforge/runtime /opt/relayforge/bin
install -d -o root -g root -m 0711 /var/lib/relayforge /var/lib/relayforge/workers
install -d -o root -g root -m 0700 /etc/relayforge /etc/relayforge/secrets \
  /etc/relayforge/secrets/tls

staging=$(mktemp -d /tmp/relayforge-install.XXXXXX)
build_dir=$(mktemp -d /tmp/relayforge-build.XXXXXX)
trap 'rm -rf -- "$staging" "$build_dir"' EXIT
install -d "$staging/config" "$staging/control" "$staging/db" "$staging/web"
install -m 0644 "$project_dir/compose.yaml" "$staging/compose.yaml"
rsync -a --exclude='__pycache__' --exclude='*.pyc' "$project_dir/config/" "$staging/config/"
rsync -a --exclude='__pycache__' --exclude='*.pyc' "$project_dir/control/" "$staging/control/"
rsync -a "$project_dir/db/" "$staging/db/"
rsync -a --exclude='__pycache__' --exclude='*.pyc' --exclude='.env' --exclude='.env.*' \
  "$project_dir/web/" "$staging/web/"
rsync -a --delete --chown=root:root --chmod=D0755,F0644 "$staging/" /opt/relayforge/app/
chmod 0555 /opt/relayforge/app/db/init/001-init.sh

for runtime_file in supervisor.py backend.py firewall.py cleanup_state.py; do
  install -o root -g root -m 0555 "$project_dir/host/$runtime_file" "/opt/relayforge/runtime/$runtime_file"
done
for runtime_script in init-challenge.sh apply-firewall.sh configure-firewall.sh harden-ssh.sh reset-lab.sh verify-hardening.sh; do
  install -o root -g root -m 0555 "$project_dir/scripts/$runtime_script" "/opt/relayforge/runtime/$runtime_script"
done

install -m 0644 "$project_dir/worker/relay-worker.c" "$project_dir/worker/Makefile" "$build_dir/"
make -C "$build_dir" clean all
install -o root -g root -m 0755 "$build_dir/relay-worker" /opt/relayforge/bin/relay-worker
readelf -h /opt/relayforge/bin/relay-worker | grep -Eq 'Type:[[:space:]]+DYN'
readelf -lW /opt/relayforge/bin/relay-worker | grep -E 'GNU_STACK' | grep -qv 'RWE'
readelf -lW /opt/relayforge/bin/relay-worker | grep -q 'GNU_RELRO'
readelf -dW /opt/relayforge/bin/relay-worker | grep -q 'BIND_NOW'

for unit in relay-supervisor.service relay-backend.service relayforge-firewall.service relayforge-stack.service; do
  install -o root -g root -m 0644 "$project_dir/host/$unit" "/etc/systemd/system/$unit"
done

signing_gid=$(getent group relayforge-signing | cut -d: -f3)
ipc_gid=$(getent group relayforge-ipc | cut -d: -f3)
dispatch_uid=$(id -u relay-dispatch)
if [[ -L $compose_environment || ( -e $compose_environment && ! -f $compose_environment ) ]]; then
  echo "Unsafe compose environment file." >&2
  exit 1
fi
if [[ -e $compose_environment && $(stat -c '%U:%G:%a' "$compose_environment") != root:root:600 ]]; then
  echo "Unsafe compose environment file." >&2
  exit 1
fi
if [[ ! -e $compose_environment ]]; then
  temporary=$(mktemp /etc/relayforge/.compose.env.XXXXXX)
  {
    printf 'POSTGRES_ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    printf 'RELAY_WEB_DB_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    printf 'RELAY_ACCESS_DB_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    printf 'RELAY_DISPATCH_DB_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    printf 'FLASK_SECRET_KEY=%s\n' "$(openssl rand -hex 32)"
    printf 'RELAY_ENDPOINT_HOST=%s\n' "$endpoint_host"
    printf 'RELAY_ENDPOINT_PORT=%s\n' "$endpoint_port"
    printf 'RELAY_IPC_GID=%s\n' "$ipc_gid"
    printf 'RELAY_SIGNING_GID=%s\n' "$signing_gid"
    printf 'DISPATCH_UID=%s\n' "$dispatch_uid"
  } >"$temporary"
  install -o root -g root -m 0600 "$temporary" "$compose_environment"
  rm -f -- "$temporary"
fi

if [[ -L $compose_environment || $(stat -c '%U:%G:%a' "$compose_environment") != root:root:600 ]]; then
  echo "Unsafe compose environment file." >&2
  exit 1
fi
line_count=0
declare -A seen_environment_keys=()
while IFS='=' read -r key value; do
  ((line_count+=1))
  if [[ -n ${seen_environment_keys[$key]:-} ]]; then
    echo "Duplicate compose environment key: $key" >&2
    exit 1
  fi
  seen_environment_keys[$key]=1
  case $key in
    POSTGRES_ADMIN_PASSWORD|RELAY_WEB_DB_PASSWORD|RELAY_ACCESS_DB_PASSWORD|RELAY_DISPATCH_DB_PASSWORD)
      [[ $value =~ ^[0-9a-f]{48}$ ]] || { echo "Invalid secret value in compose environment." >&2; exit 1; } ;;
    FLASK_SECRET_KEY)
      [[ $value =~ ^[0-9a-f]{64}$ ]] || { echo "Invalid Flask secret in compose environment." >&2; exit 1; } ;;
    RELAY_ENDPOINT_HOST) [[ $value == "$endpoint_host" ]] || { echo "Endpoint host changed; reset/reinstall with the recorded endpoint." >&2; exit 1; } ;;
    RELAY_ENDPOINT_PORT) [[ $value == "$endpoint_port" ]] || { echo "Endpoint port changed; reset/reinstall with the recorded endpoint." >&2; exit 1; } ;;
    RELAY_IPC_GID) [[ $value == "$ipc_gid" ]] || { echo "IPC GID changed." >&2; exit 1; } ;;
    RELAY_SIGNING_GID) [[ $value == "$signing_gid" ]] || { echo "Signing GID changed." >&2; exit 1; } ;;
    DISPATCH_UID) [[ $value == "$dispatch_uid" ]] || { echo "Dispatcher UID changed." >&2; exit 1; } ;;
    *) echo "Unknown compose environment key: $key" >&2; exit 1 ;;
  esac
done <"$compose_environment"
if [[ $line_count -ne 10 ]]; then
  echo "Compose environment must contain exactly ten entries; deploy this schema from a fresh snapshot." >&2
  exit 1
fi

private_key=/etc/relayforge/secrets/job-signing.pem
public_key=/etc/relayforge/job-signing.pub
if [[ ! -e $private_key ]]; then
  temporary=$(mktemp /etc/relayforge/secrets/.job-signing.XXXXXX)
  openssl genpkey -algorithm ED25519 -out "$temporary"
  install -o root -g relayforge-signing -m 0440 "$temporary" "$private_key"
  rm -f -- "$temporary"
fi
if [[ -L $private_key || $(stat -c '%U:%G:%a' "$private_key") != root:relayforge-signing:440 ]]; then
  echo "Unsafe signing-key ownership or mode." >&2
  exit 1
fi
temporary=$(mktemp /etc/relayforge/.job-signing.pub.XXXXXX)
openssl pkey -in "$private_key" -pubout -out "$temporary"
install -o root -g root -m 0444 "$temporary" "$public_key"
rm -f -- "$temporary"

tls_key=/etc/relayforge/secrets/tls/server.key
tls_certificate=/etc/relayforge/secrets/tls/server.crt
if [[ ! -e $tls_key || ! -e $tls_certificate ]]; then
  rm -f -- "$tls_key" "$tls_certificate"
  openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
    -subj '/CN=relayforge.local' -addext 'subjectAltName=DNS:relayforge.local' \
    -keyout "$tls_key" -out "$tls_certificate"
fi
chown root:root "$tls_key" "$tls_certificate"
chmod 0400 "$tls_key"
chmod 0444 "$tls_certificate"

firewall_environment=/etc/relayforge/firewall.env
temporary=$(mktemp /etc/relayforge/.firewall.env.XXXXXX)
{
  printf 'PLAYER_CIDR=%s\n' "$player_cidr"
  printf 'PUBLIC_IFACE=%s\n' "$public_interface"
  printf 'ENDPOINT_HOST=%s\n' "$endpoint_host"
  printf 'ENDPOINT_PORT=%s\n' "$endpoint_port"
  printf 'FIREWALL_DEFERRED=%s\n' "$defer_firewall"
} >"$temporary"
install -o root -g root -m 0600 "$temporary" "$firewall_environment"
rm -f -- "$temporary"

temporary=$(mktemp /etc/relayforge/.install.state.XXXXXX)
{
  printf 'FIREWALL_DEFERRED=%s\n' "$defer_firewall"
  printf 'SSH_DEFERRED=%s\n' "$defer_ssh"
  printf 'ADMIN_USER=%s\n' "$admin_user"
} >"$temporary"
install -o root -g root -m 0600 "$temporary" /etc/relayforge/install.state
rm -f -- "$temporary"

install -o root -g root -m 0644 "$project_dir/config/60-relayforge-sysctl.conf" \
  /etc/sysctl.d/60-relayforge.conf
sysctl --system >/dev/null
/opt/relayforge/runtime/init-challenge.sh
if [[ $defer_ssh -eq 0 ]]; then
  /opt/relayforge/runtime/harden-ssh.sh "$admin_user"
fi

systemctl daemon-reload
/usr/bin/docker compose --project-directory /opt/relayforge/app \
  --env-file "$compose_environment" config --quiet
/usr/bin/docker compose --project-directory /opt/relayforge/app \
  --env-file "$compose_environment" pull edge postgres
/usr/bin/docker compose --project-directory /opt/relayforge/app \
  --env-file "$compose_environment" build --pull

if [[ $defer_firewall -eq 1 ]]; then
  systemctl disable --now relayforge-stack.service relayforge-firewall.service \
    relay-supervisor.service relay-backend.service 2>/dev/null || true
  echo "Installed and built, but intentionally left stopped until firewall configuration is supplied."
  echo "Hardening verification will fail while FIREWALL_DEFERRED=1."
  exit 0
fi

systemctl enable relay-backend.service relay-supervisor.service \
  relayforge-firewall.service relayforge-stack.service
systemctl restart relay-backend.service relay-supervisor.service
systemctl restart relayforge-firewall.service
systemctl restart relayforge-stack.service
/opt/relayforge/runtime/verify-hardening.sh
echo "RelayForge installation and hardening verification completed."
