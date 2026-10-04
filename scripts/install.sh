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
acknowledge_unrestricted_root=0

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
  --acknowledge-unrestricted-root
                          REQUIRED: confirm this CTF deliberately grants an
                          attacker unrestricted UID-0 execution on the host

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
    --acknowledge-unrestricted-root) acknowledge_unrestricted_root=1; shift ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "Run the installer as root (normally with sudo)." >&2
  exit 1
fi
if [[ $acknowledge_unrestricted_root -ne 1 ]]; then
  echo "REFUSING INSTALL: this branch intentionally provides unrestricted host-root code execution." >&2
  echo "Use only a disposable, single-player VM with no IAM role, credentials, or valuable data." >&2
  echo "Rerun with --acknowledge-unrestricted-root only after accepting that risk." >&2
  exit 64
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

# Reject known secret drift before package installation or service downtime.
# An operator must inspect and repair/rotate an existing key deliberately.
existing_private_key=/etc/relayforge/secrets/job-signing.pem
if [[ -e $existing_private_key ]] && {
     [[ -L $existing_private_key ]] ||
     [[ ! -f $existing_private_key ]] ||
     [[ $(stat -c '%U:%G:%a' "$existing_private_key") != root:relayforge-signing:440 ]];
   }; then
  echo "Unsafe existing signing-key ownership or mode; inspect it before installation." >&2
  exit 1
fi

for selected in control db web config host scripts worker; do
  if find "$project_dir/$selected" -type l -print -quit | grep -q .; then
    echo "Refusing a source tree containing symbolic links: $selected" >&2
    exit 1
  fi
done

# Installing/upgrading Docker may restart its daemon and interrupt every
# running container.  Check before apt changes anything.  RelayForge is a
# dedicated-host lab, so refuse when another Compose project (or an unlabelled
# container) is active.  Stopped foreign containers are left untouched.
if systemctl is-active --quiet docker.service && command -v docker >/dev/null 2>&1; then
  foreign_containers=$(
    docker ps --format '{{.ID}} {{.Names}} {{.Label "com.docker.compose.project"}}' |
      awk 'NF < 3 || $3 != "relayforge" { print }'
  )
  if [[ -n $foreign_containers ]]; then
    echo "Refusing to reconcile a host with non-RelayForge containers running:" >&2
    printf '%s\n' "$foreign_containers" >&2
    exit 1
  fi
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  binutils build-essential ca-certificates docker.io docker-compose-v2 iproute2 \
  iptables openssh-server openssl python3 python3-cryptography rsync

install -d -o root -g root -m 0755 /etc/docker
docker_restart_required=0
if [[ -e /etc/docker/daemon.json ]]; then
  if ! cmp -s "$project_dir/config/docker-daemon.json" /etc/docker/daemon.json; then
    echo "Existing /etc/docker/daemon.json differs; refusing to overwrite it." >&2
    exit 1
  fi
else
  install -o root -g root -m 0644 "$project_dir/config/docker-daemon.json" /etc/docker/daemon.json
  docker_restart_required=1
fi
systemctl enable docker.service
if systemctl is-active --quiet docker.service; then
  if [[ $docker_restart_required -eq 1 ]]; then
    systemctl stop relayforge-stack.service 2>/dev/null || true
    systemctl restart docker.service
  fi
else
  systemctl start docker.service
fi
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

# Stop only the services whose on-disk programs/build contexts are about to be
# reconciled.  Existing transient Workers are deliberately preserved: systemd
# owns their running executables and the restarted Supervisor restores their
# exact UUID state.
systemctl stop relayforge-stack.service 2>/dev/null || true
systemctl stop relay-supervisor.service relay-backend.service 2>/dev/null || true

# Remove exact units from the superseded timer/permanent-Worker prototypes.
# No wildcard is used here, so current services and transient
# relay-worker-<UUID>.service units cannot be deleted by this cleanup.
legacy_units=(
  relay-cleanup.service
  relay-cleanup.timer
  relay-rotate.service
  relay-rotate.timer
  relay-worker.service
)
systemctl disable --now "${legacy_units[@]}" 2>/dev/null || true
for legacy_unit in "${legacy_units[@]}"; do
  rm -f -- "/etc/systemd/system/$legacy_unit"
  systemctl reset-failed "$legacy_unit" 2>/dev/null || true
done

# The earlier bounded-root prototype installed this one systemctl-edit
# override.  Keep its useful runtime-directory preservation in the canonical
# unit, but remove the exact known file because its five-capability ceiling
# contradicts this branch's deliberately unrestricted host-root objective.
# Any different drop-in is administrator-owned unknown state and fails closed.
legacy_supervisor_dropin_dir=/etc/systemd/system/relay-supervisor.service.d
legacy_supervisor_dropin=$legacy_supervisor_dropin_dir/override.conf
if [[ -L $legacy_supervisor_dropin_dir || \
      ( -e $legacy_supervisor_dropin_dir && ! -d $legacy_supervisor_dropin_dir ) ]]; then
  echo "Unsafe Supervisor drop-in path." >&2
  exit 1
fi
if [[ -d $legacy_supervisor_dropin_dir ]]; then
  mapfile -t supervisor_dropin_entries < <(
    find "$legacy_supervisor_dropin_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort
  )
  expected_legacy_dropin=$'[Service]\nRuntimeDirectory=relayforge\nRuntimeDirectoryMode=0750\nRuntimeDirectoryPreserve=yes\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER CAP_SETUID CAP_SETGID'
  normalized_legacy_dropin=$(
    sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$legacy_supervisor_dropin" 2>/dev/null || true
  )
  if [[ ${#supervisor_dropin_entries[@]} -ne 1 || \
        ${supervisor_dropin_entries[0]:-} != override.conf || \
        -L $legacy_supervisor_dropin || ! -f $legacy_supervisor_dropin || \
        $(stat -c '%U:%G:%a' "$legacy_supervisor_dropin" 2>/dev/null || true) != root:root:644 || \
        $normalized_legacy_dropin != "$expected_legacy_dropin" ]]; then
    echo "Unknown Supervisor drop-in; inspect it instead of deleting it." >&2
    exit 1
  fi
  rm -f -- "$legacy_supervisor_dropin"
  rmdir -- "$legacy_supervisor_dropin_dir"
fi
systemctl daemon-reload

# All three /opt trees below are owned exclusively by RelayForge.  Refuse
# symlink/non-directory substitutions before rsync --delete applies the exact
# runtime allowlists.
for managed_directory in \
  /opt/relayforge \
  /opt/relayforge/app \
  /opt/relayforge/runtime \
  /opt/relayforge/bin; do
  if [[ -L $managed_directory || ( -e $managed_directory && ! -d $managed_directory ) ]]; then
    echo "Unsafe managed path: $managed_directory" >&2
    exit 1
  fi
  if [[ -d $managed_directory && $(stat -c '%U:%G' "$managed_directory") != root:root ]]; then
    echo "Managed path is not root-owned: $managed_directory" >&2
    exit 1
  fi
done

install -d -o root -g root -m 0755 /opt/relayforge /opt/relayforge/app \
  /opt/relayforge/runtime /opt/relayforge/bin
install -d -o root -g root -m 0711 /var/lib/relayforge /var/lib/relayforge/workers \
  /var/lib/relayforge/stages
install -d -o root -g root -m 0700 /etc/relayforge /etc/relayforge/secrets \
  /etc/relayforge/secrets/tls
install -o root -g relayforge-ipc -m 0440 "$project_dir/host/STAGE_2_WORKER.txt" \
  /var/lib/relayforge/stages/STAGE_2_WORKER.txt
install -o root -g root -m 0400 "$project_dir/host/STAGE_3_ROOT.txt" \
  /var/lib/relayforge/stages/STAGE_3_ROOT.txt

staging=$(mktemp -d /tmp/relayforge-install.XXXXXX)
build_dir=$(mktemp -d /tmp/relayforge-build.XXXXXX)
trap 'rm -rf -- "$staging" "$build_dir"' EXIT
app_stage=$staging/app
runtime_stage=$staging/runtime
bin_stage=$staging/bin
install -d \
  "$app_stage/config" \
  "$app_stage/control" \
  "$app_stage/db/init" \
  "$app_stage/web/app" \
  "$app_stage/web/static" \
  "$app_stage/web/templates" \
  "$runtime_stage" \
  "$bin_stage"

# Compose runtime allowlist.  Repository tests, exploit helpers, READMEs and
# host-only sysctl/Docker configuration never enter /opt/relayforge/app.
install -m 0644 "$project_dir/compose.yaml" "$app_stage/compose.yaml"
install -m 0644 "$project_dir/config/nginx.conf" "$app_stage/config/nginx.conf"
for control_file in \
  Dockerfile requirements.txt common.py policy.py access.py dispatcher.py healthcheck.py; do
  install -m 0644 "$project_dir/control/$control_file" "$app_stage/control/$control_file"
done
install -m 0755 "$project_dir/db/init/001-init.sh" "$app_stage/db/init/001-init.sh"
install -m 0644 "$project_dir/db/init/002-schema.sql.in" "$app_stage/db/init/002-schema.sql.in"
for web_file in .dockerignore Dockerfile requirements.txt prefs.py STAGE_1_WEB.txt; do
  install -m 0644 "$project_dir/web/$web_file" "$app_stage/web/$web_file"
done
for web_module in __init__.py auth.py config.py db.py raw_rpc.py; do
  install -m 0644 "$project_dir/web/app/$web_module" "$app_stage/web/app/$web_module"
done
install -m 0644 "$project_dir/web/static/style.css" "$app_stage/web/static/style.css"
for web_template in base.html connection.html cookie_policy.html dashboard.html login.html; do
  install -m 0644 "$project_dir/web/templates/$web_template" \
    "$app_stage/web/templates/$web_template"
done
rsync -a --delete --chown=root:root --chmod=D0755,F0644 "$app_stage/" /opt/relayforge/app/
chmod 0555 /opt/relayforge/app/db/init/001-init.sh

for runtime_file in supervisor.py backend.py firewall.py cleanup_state.py; do
  install -m 0555 "$project_dir/host/$runtime_file" "$runtime_stage/$runtime_file"
done
for runtime_script in init-challenge.sh configure-firewall.sh harden-ssh.sh reset-lab.sh verify-hardening.sh; do
  install -m 0555 "$project_dir/scripts/$runtime_script" "$runtime_stage/$runtime_script"
done
rsync -a --delete --chown=root:root "$runtime_stage/" /opt/relayforge/runtime/

install -m 0644 "$project_dir/worker/relay-worker.c" "$project_dir/worker/Makefile" "$build_dir/"
make -C "$build_dir" clean all
install -m 0755 "$build_dir/relay-worker" "$bin_stage/relay-worker"
rsync -a --delete --chown=root:root "$bin_stage/" /opt/relayforge/bin/
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
  printf 'UNRESTRICTED_ROOT_ACK=1\n'
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

if ss -ltnH | awk '{print $4}' | grep -Eq '(^|:)443$'; then
  echo "TCP 443 is already in use after stopping RelayForge; remove the conflicting host service." >&2
  ss -ltnp '( sport = :443 )' >&2 || true
  exit 1
fi
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
  echo "Deployment verification will fail while FIREWALL_DEFERRED=1."
  exit 0
fi

systemctl enable relay-backend.service relay-supervisor.service \
  relayforge-firewall.service relayforge-stack.service
systemctl restart relay-backend.service relay-supervisor.service
systemctl restart relayforge-firewall.service
systemctl restart relayforge-stack.service
/opt/relayforge/runtime/verify-hardening.sh
apt-get clean
echo "RelayForge unrestricted-root installation and deployment verification completed."
