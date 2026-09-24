#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
image='ubuntu:24.04@sha256:a61567bd31828687156d735ea8eb01ba4e37636e225dd6a48ba94136a70d9d61'
docker run --rm --platform linux/amd64 \
  --mount "type=bind,src=$root,dst=/source,readonly" \
  "$image" bash -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends python3 systemd >/dev/null
    groupadd --system relayforge-ipc
    groupadd --system relay-backend
    useradd --system --gid relay-backend --home-dir /nonexistent --no-create-home relay-backend
    install -d /etc/systemd/system /opt/relayforge/runtime /opt/relayforge/app /var/lib/relayforge/workers
    install -m 0755 /bin/true /opt/relayforge/runtime/supervisor.py
    install -m 0755 /bin/true /opt/relayforge/runtime/backend.py
    install -m 0755 /bin/true /opt/relayforge/runtime/firewall.py
    install -m 0755 /bin/true /usr/bin/docker
    cp /source/host/*.service /etc/systemd/system/
    printf "%s\n" "[Service]" "ExecStart=/bin/true" > /etc/systemd/system/docker.service
    systemd-analyze verify \
      /etc/systemd/system/docker.service \
      /etc/systemd/system/relay-backend.service \
      /etc/systemd/system/relay-supervisor.service \
      /etc/systemd/system/relayforge-firewall.service \
      /etc/systemd/system/relayforge-stack.service
    systemd-analyze --version | grep -Eq "^systemd (25[5-9]|2[6-9][0-9]|[3-9][0-9]{2})"
  '
echo "PASS: all systemd units validate with Ubuntu 24.04 systemd 255+"
