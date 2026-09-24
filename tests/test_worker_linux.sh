#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
image='ubuntu:24.04@sha256:a61567bd31828687156d735ea8eb01ba4e37636e225dd6a48ba94136a70d9d61'
docker run --rm --platform linux/amd64 \
  --mount "type=bind,src=$root,dst=/source,readonly" \
  "$image" bash -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends binutils build-essential python3 >/dev/null
    test "$(dpkg --print-architecture)" = amd64
    grep -q "VERSION_ID=\"24.04\"" /etc/os-release
    mkdir -p /tmp/relayforge/worker /tmp/relayforge/tests
    cp /source/worker/Makefile /source/worker/relay-worker.c /tmp/relayforge/worker/
    cp /source/tests/test_worker.py /tmp/relayforge/tests/
    python3 /tmp/relayforge/tests/test_worker.py
    make -C /tmp/relayforge/worker all >/dev/null
    readelf -h /tmp/relayforge/worker/relay-worker | grep -Eq "Type:[[:space:]]+DYN"
    readelf -lW /tmp/relayforge/worker/relay-worker | grep GNU_STACK | grep -qv RWE
    readelf -lW /tmp/relayforge/worker/relay-worker | grep -q GNU_RELRO
    readelf -dW /tmp/relayforge/worker/relay-worker | grep -q BIND_NOW
    readelf -sW /tmp/relayforge/worker/relay-worker | grep -q __stack_chk_fail
  '
echo "PASS: Worker exploit and ELF hardening on Ubuntu 24.04 AMD64"
