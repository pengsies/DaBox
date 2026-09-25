#!/usr/bin/env bash
set -uo pipefail
umask 077

passes=0
failures=0
pass() { printf 'PASS  %s\n' "$1"; ((passes+=1)); }
fail() { printf 'FAIL  %s\n' "$1" >&2; ((failures+=1)); }
expect_command() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then pass "$label"; else fail "$label"; fi
}
expect_file() {
  local path=$1 owner=$2 group=$3 mode=$4 label=$5
  local observed
  if [[ -L $path || ! -f $path ]]; then fail "$label"; return; fi
  observed=$(stat -c '%U:%G:%a' "$path" 2>/dev/null || true)
  if [[ $observed == "$owner:$group:$mode" ]]; then pass "$label"; else fail "$label ($observed)"; fi
}

if [[ ${EUID} -ne 0 ]]; then
  echo "Run verification as root." >&2
  exit 1
fi

os_id=$(sed -n 's/^ID=//p' /etc/os-release | head -n1 | tr -d '"')
os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | head -n1 | tr -d '"')
if [[ $os_id == ubuntu && $os_version == 24.04 && $(uname -m) == x86_64 ]]; then
  pass "Ubuntu 24.04.x AMD64 host"
else
  fail "Ubuntu 24.04.x AMD64 host"
fi

for unit in docker.service relay-backend.service relay-supervisor.service relayforge-firewall.service relayforge-stack.service; do
  expect_command "$unit is active" systemctl is-active --quiet "$unit"
  expect_command "$unit is enabled" systemctl is-enabled --quiet "$unit"
done

if grep -qx 'FIREWALL_DEFERRED=0' /etc/relayforge/install.state 2>/dev/null; then
  pass "firewall was not deferred"
else
  fail "firewall was not deferred"
fi
if grep -qx 'SSH_DEFERRED=0' /etc/relayforge/install.state 2>/dev/null; then
  pass "SSH hardening was not deferred"
else
  fail "SSH hardening was not deferred"
fi
if grep -qx 'UNRESTRICTED_ROOT_ACK=1' /etc/relayforge/install.state 2>/dev/null; then
  pass "unrestricted-root challenge mode was explicitly acknowledged"
else
  fail "unrestricted-root challenge mode was explicitly acknowledged"
fi

expect_file /etc/relayforge/compose.env root root 600 "Compose secrets are root-only"
expect_file /etc/relayforge/firewall.env root root 600 "firewall configuration is root-only"
expect_file /etc/relayforge/secrets/job-signing.pem root relayforge-signing 440 "signing key has narrow group-read access"
expect_file /etc/relayforge/job-signing.pub root root 444 "verification key is immutable to services"
expect_file /etc/relayforge/secrets/tls/server.key root root 400 "TLS private key is root-only"
expect_file /var/lib/relayforge/flag/root.txt root root 600 "root flag is root-only"
expect_file /opt/relayforge/bin/relay-worker root root 755 "Worker executable is root-owned"

if find /opt/relayforge -xdev \( -type f -o -type d \) -perm /0022 -print -quit | grep -q .; then
  fail "runtime tree has no group/world-writable entries"
else
  pass "runtime tree has no group/world-writable entries"
fi
# Exclude this verifier because the search expression below is intentionally
# present in its own source and is not private-key material.
if grep -RIlE --exclude='*.pub' --exclude='verify-hardening.sh' \
    -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' /opt/relayforge 2>/dev/null | grep -q .; then
  fail "runtime application tree contains no private keys"
else
  pass "runtime application tree contains no private keys"
fi

expect_command "Worker is PIE" bash -c "readelf -h /opt/relayforge/bin/relay-worker | grep -Eq 'Type:[[:space:]]+DYN'"
expect_command "Worker stack is non-executable" bash -c "readelf -lW /opt/relayforge/bin/relay-worker | grep GNU_STACK | grep -qv RWE"
expect_command "Worker has GNU RELRO" bash -c "readelf -lW /opt/relayforge/bin/relay-worker | grep -q GNU_RELRO"
expect_command "Worker has immediate binding/full RELRO" bash -c "readelf -dW /opt/relayforge/bin/relay-worker | grep -q BIND_NOW"

supervisor_properties=$(systemctl show relay-supervisor.service \
  -p User -p Group -p NoNewPrivileges -p ProtectSystem -p ProtectHome \
  -p PrivateDevices -p RestrictSUIDSGID -p MemoryDenyWriteExecute \
  -p CapabilityBoundingSet 2>/dev/null)
if [[ $supervisor_properties == *$'User=root'* && \
      $supervisor_properties == *$'Group=relayforge-ipc'* && \
      $supervisor_properties == *$'NoNewPrivileges=no'* && \
      $supervisor_properties == *$'ProtectSystem=no'* && \
      $supervisor_properties == *$'ProtectHome=no'* && \
      $supervisor_properties == *$'PrivateDevices=no'* && \
      $supervisor_properties == *$'RestrictSUIDSGID=no'* && \
      $supervisor_properties == *$'MemoryDenyWriteExecute=no'* ]]; then
  pass "Supervisor is intentionally unrestricted for the host-root challenge"
else
  fail "Supervisor is intentionally unrestricted for the host-root challenge"
fi
supervisor_capabilities=${supervisor_properties,,}
if [[ $supervisor_capabilities == *cap_chown* && \
      $supervisor_capabilities == *cap_dac_override* && \
      $supervisor_capabilities == *cap_net_admin* && \
      $supervisor_capabilities == *cap_sys_admin* && \
      $supervisor_capabilities == *cap_sys_ptrace* ]]; then
  pass "Supervisor retains the host-root capability boundary intentionally"
else
  fail "Supervisor retains the host-root capability boundary intentionally"
fi

socket_metadata=$(stat -c '%U:%G:%a:%F' /run/relayforge/supervisor.sock 2>/dev/null || true)
if [[ $socket_metadata == 'root:relayforge-ipc:660:socket' ]]; then
  pass "Supervisor socket peer boundary"
else
  fail "Supervisor socket peer boundary ($socket_metadata)"
fi

expect_command "IPv4 host firewall hook" iptables -C INPUT -j RF_INPUT
expect_command "relay egress firewall hook" iptables -C OUTPUT -j RF_OUTPUT
expect_command "Docker user firewall hook" iptables -C DOCKER-USER -j RF_DOCKER
expect_command "IPv6 input firewall hook" ip6tables -C INPUT -j RF6_INPUT
player_cidr=$(sed -n 's/^PLAYER_CIDR=//p' /etc/relayforge/firewall.env 2>/dev/null)
public_interface=$(sed -n 's/^PUBLIC_IFACE=//p' /etc/relayforge/firewall.env 2>/dev/null)
ssh_rule=$(iptables -S RF_INPUT 2>/dev/null | grep -- '--dport 22' || true)
if [[ -n $player_cidr && -n $public_interface ]] && \
   [[ $(printf '%s\n' "$ssh_rule" | grep -c .) -eq 1 ]] && \
   [[ $ssh_rule == *"-i $public_interface"* && $ssh_rule != *' -s '* ]] && \
   iptables -C RF_INPUT -i "$public_interface" -s "$player_cidr" -p tcp \
     --dport 443 -j ACCEPT >/dev/null 2>&1 && \
   iptables -C RF_INPUT -i "$public_interface" -s "$player_cidr" -p tcp \
     --dport 25000:25099 -j ACCEPT >/dev/null 2>&1 && \
   iptables -S RF_DOCKER 2>/dev/null | grep -q -- '--ctorigdstport 443'; then
  pass "key-only SSH is public and HTTPS/Worker gates match PLAYER_CIDR"
else
  fail "key-only SSH is public and HTTPS/Worker gates match PLAYER_CIDR"
fi
endpoint_host=$(sed -n 's/^ENDPOINT_HOST=//p' /etc/relayforge/firewall.env 2>/dev/null)
endpoint_port=$(sed -n 's/^ENDPOINT_PORT=//p' /etc/relayforge/firewall.env 2>/dev/null)
if [[ -n $endpoint_host && -n $endpoint_port ]] && \
   iptables -C RF_OUTPUT -m owner --uid-owner relay -d "$endpoint_host/32" \
     -p tcp --dport "$endpoint_port" -j RETURN >/dev/null 2>&1; then
  pass "relay IP egress is limited to the registered endpoint and established replies"
else
  fail "relay IP egress is limited to the registered endpoint and established replies"
fi

if ss -ltnH | awk '{print $4}' | grep -Eq '(^|:)5432$'; then
  fail "PostgreSQL is not listening in the host namespace"
else
  pass "PostgreSQL is not listening in the host namespace"
fi
if ss -ltnH | awk '{print $4}' | grep -Eq '^127\.0\.0\.1:19001$'; then
  pass "HTTP endpoint fixture listens only on IPv4 loopback"
else
  fail "HTTP endpoint fixture listens only on IPv4 loopback"
fi

project=/opt/relayforge/app
environment=/etc/relayforge/compose.env
compose=(/usr/bin/docker compose --project-directory "$project" --env-file "$environment")
expect_command "Compose configuration renders" "${compose[@]}" config --quiet
running_count=$("${compose[@]}" ps --status running --quiet 2>/dev/null | wc -l)
if [[ $running_count -eq 5 ]]; then
  pass "all five containers are running"
else
  fail "all five containers are running ($running_count)"
fi
unhealthy=0
while read -r container_id; do
  [[ -n $container_id ]] || continue
  health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$container_id" 2>/dev/null || true)
  [[ $health == healthy ]] || unhealthy=$((unhealthy+1))
  privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' "$container_id" 2>/dev/null || true)
  readonly=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container_id" 2>/dev/null || true)
  binds=$(docker inspect --format '{{json .HostConfig.Binds}}' "$container_id" 2>/dev/null || true)
  [[ $privileged == false && $readonly == true && $binds != *docker.sock* ]] || unhealthy=$((unhealthy+1))
done < <("${compose[@]}" ps --quiet)
if [[ $unhealthy -eq 0 ]]; then
  pass "containers are healthy, unprivileged, read-only, and lack Docker socket"
else
  fail "container runtime controls ($unhealthy violations)"
fi

edge_id=$("${compose[@]}" ps --quiet edge 2>/dev/null)
published=$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$edge_id" 2>/dev/null || true)
if [[ $published == *'"443/tcp"'* && $published == *'"HostIp":"0.0.0.0"'* && \
      $published != *'5432'* && $published != *'8080'* ]]; then
  pass "only edge HTTPS is Docker-published"
else
  fail "only edge HTTPS is Docker-published"
fi

db=("${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d relayforge)
if "${db[@]}" -Atqc "SELECT NOT has_database_privilege('relay_web','relayforge','TEMP') AND NOT has_schema_privilege('relay_web','private','USAGE') AND has_function_privilege('relay_web','relay_web_api.submit_raw_request(text,text,text,integer,text)','EXECUTE');" 2>/dev/null | grep -qx t; then
  pass "relay_web has only the intended RPC capability boundary"
else
  fail "relay_web has only the intended RPC capability boundary"
fi
if "${db[@]}" -qc 'SET ROLE relay_web; SELECT * FROM private.jobs LIMIT 1;' >/dev/null 2>&1; then
  fail "relay_web cannot read private job tables"
else
  pass "relay_web cannot read private job tables"
fi
if "${db[@]}" -Atqc "SELECT NOT has_function_privilege('relay_web','relay_access_api.claim_request()','EXECUTE') AND NOT has_function_privilege('relay_web','relay_dispatch_api.claim_job()','EXECUTE');" 2>/dev/null | grep -qx t; then
  pass "web role cannot claim or dispatch signed jobs"
else
  fail "web role cannot claim or dispatch signed jobs"
fi

if grep -nE "submit_raw_request|_request_value\\([\"']options[\"']" \
    "$project/web/app/__init__.py" "$project/web/app/auth.py" 2>/dev/null | grep -q .; then
  fail "public Flask routes cannot submit raw options"
else
  pass "public Flask routes cannot submit raw options"
fi

sshd_effective=$(/usr/sbin/sshd -T 2>/dev/null || true)
if [[ $sshd_effective == *$'passwordauthentication no'* && \
      $sshd_effective == *$'kbdinteractiveauthentication no'* && \
      $sshd_effective == *$'permitrootlogin no'* && \
      $sshd_effective == *$'allowtcpforwarding no'* ]]; then
  pass "effective SSH policy is key-only and forwarding-disabled"
else
  fail "effective SSH policy is key-only and forwarding-disabled"
fi

printf '\nSummary: %d passed, %d failed\n' "$passes" "$failures"
[[ $failures -eq 0 ]]
