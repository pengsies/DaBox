#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "usage: tests/run-vm.sh HTTPS_TARGET" >&2
  exit 64
fi
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
python3 "$root/tests/negative_paths.py" "$1"
python3 "$root/attacks/full_chain.py" "$1"
