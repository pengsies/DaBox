#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
compose=(
  docker compose
  --project-directory "$root/tests"
  -f "$root/tests/compose.endpoint.yaml"
)

cleanup() {
  "${compose[@]}" down --remove-orphans --timeout 10 >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

command -v docker >/dev/null
command -v make >/dev/null
command -v python3 >/dev/null
docker compose version >/dev/null

"${compose[@]}" down --remove-orphans --timeout 10
"${compose[@]}" up --detach --wait

container_id=$("${compose[@]}" ps --quiet sample-endpoint)
publication=$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$container_id")
[[ $publication == '{"19001/tcp":[{"HostIp":"127.0.0.1","HostPort":"19001"}]}' ]] || {
  echo "FAIL: endpoint publication is not loopback-only: $publication" >&2
  exit 1
}

security=$(docker inspect --format \
  '{{.Config.User}}|{{.HostConfig.Privileged}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}' \
  "$container_id")
[[ $security == '65532:65532|false|true|["ALL"]|["no-new-privileges:true"]|32|67108864' ]] || {
  echo "FAIL: endpoint container boundary is unsafe: $security" >&2
  exit 1
}

binds=$(docker inspect --format '{{json .HostConfig.Binds}}' "$container_id")
[[ $binds == *"$root/tests/sample_endpoint.py:/sample_endpoint.py:ro"* && $binds != *,* ]] || {
  echo "FAIL: endpoint container mount is unexpected: $binds" >&2
  exit 1
}

internal=$(docker network inspect --format '{{.Internal}}' relayforge-endpoint-test_endpoint_net)
[[ $internal == false ]] || {
  echo "FAIL: endpoint publication unexpectedly uses an internal-only network" >&2
  exit 1
}

python3 "$root/tests/sample_endpoint.py" --healthcheck
python3 "$root/tests/test_worker_endpoint.py"
echo "PASS: loopback-only Docker endpoint and real Worker tunnel integration"
