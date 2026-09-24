#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$root"
# Fast source/component suite. Linux-specific, netfilter, systemd, and live
# container tests have dedicated runners documented in README.md.
python3 tests/check_shared_snapshot.py
python3 tests/static_audit.py
python3 tests/check_integrated_stage.py
python3 tests/test_python_syntax.py
python3 tests/test_policy.py
python3 tests/test_supervisor.py
python3 tests/test_pickle_payload.py
python3 tests/test_firewall_policy.py
bash -n scripts/*.sh tests/*.sh db/init/*.sh
echo "PASS: shell syntax"
docker compose --env-file .env.example config --quiet
echo "PASS: Compose model renders"
python3 tests/test_worker.py
