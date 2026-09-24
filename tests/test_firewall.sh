#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
image='ubuntu:24.04@sha256:a61567bd31828687156d735ea8eb01ba4e37636e225dd6a48ba94136a70d9d61'
docker run --rm --platform linux/amd64 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --mount "type=bind,src=$root,dst=/source,readonly" \
  "$image" bash -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends iptables python3 >/dev/null
    useradd --system --home-dir /nonexistent --no-create-home relay
    iptables -N DOCKER-USER
    install -d -m 0700 /etc/relayforge
    printf "%s\n" \
      "PLAYER_CIDR=0.0.0.0/0" \
      "PUBLIC_IFACE=lo" \
      "ENDPOINT_HOST=127.0.0.1" \
      "ENDPOINT_PORT=19001" \
      "FIREWALL_DEFERRED=0" > /etc/relayforge/firewall.env
    chmod 0600 /etc/relayforge/firewall.env
    python3 /source/host/firewall.py --config /etc/relayforge/firewall.env
    python3 /source/host/firewall.py --config /etc/relayforge/firewall.env
    test "$(iptables -S INPUT | grep -c -- "-j RF_INPUT")" -eq 1
    test "$(iptables -S OUTPUT | grep -c -- "-j RF_OUTPUT")" -eq 1
    test "$(iptables -S DOCKER-USER | grep -c -- "-j RF_DOCKER")" -eq 1
    ssh_rule=$(iptables -S RF_INPUT | grep -- "--dport 22")
    test "$(printf "%s\n" "$ssh_rule" | wc -l)" -eq 1
    printf "%s\n" "$ssh_rule" | grep -q -- "-i lo"
    if printf "%s\n" "$ssh_rule" | grep -q -- " -s "; then
      echo "SSH recovery rule is source-restricted" >&2
      exit 1
    fi
    iptables -C RF_INPUT -i lo -s 0.0.0.0/0 -p tcp --dport 443 -j ACCEPT
    iptables -C RF_INPUT -i lo -s 0.0.0.0/0 -p tcp --dport 25000:25099 -j ACCEPT
    iptables -S RF_INPUT | grep -q -- "--dport 25000:25099"
    iptables -S RF_DOCKER | grep -q -- "--ctorigdstport 443"
    iptables -S RF_OUTPUT | grep -q -- "--uid-owner"
    iptables -S RF_OUTPUT | grep -q -- "-d 127.0.0.1/32"
    iptables -S RF_OUTPUT | grep -q -- "--dport 19001"
    ip6tables -C INPUT -j RF6_INPUT
    ln -s /etc/relayforge/firewall.env /etc/relayforge/firewall-link.env
    if python3 /source/host/firewall.py --config /etc/relayforge/firewall-link.env >/dev/null 2>&1; then
      echo "symlinked firewall config was accepted" >&2
      exit 1
    fi
    chmod 0666 /etc/relayforge/firewall.env
    if python3 /source/host/firewall.py --config /etc/relayforge/firewall.env >/dev/null 2>&1; then
      echo "unsafe firewall config was accepted" >&2
      exit 1
    fi
  '
echo "PASS: firewall permits public key-only SSH/player access, applies idempotently, and rejects unsafe configuration"
