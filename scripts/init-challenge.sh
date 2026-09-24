#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi
if [[ $# -gt 1 || ( $# -eq 1 && $1 != --rotate ) ]]; then
  echo "usage: init-challenge.sh [--rotate]" >&2
  exit 64
fi

flag_dir=/var/lib/relayforge/flag
flag_path=$flag_dir/root.txt
install -d -o root -g root -m 0700 "$flag_dir"
if [[ ! -e $flag_path || ${1:-} == --rotate ]]; then
  temporary=$(mktemp "$flag_dir/.root.txt.XXXXXX")
  trap 'rm -f -- "$temporary"' EXIT
  printf 'RF{%s}\n' "$(openssl rand -hex 16)" >"$temporary"
  chown root:root "$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$flag_path"
  trap - EXIT
fi

owner=$(stat -c '%U:%G' "$flag_path")
mode=$(stat -c '%a' "$flag_path")
if [[ $owner != root:root || $mode != 600 || -L $flag_path ]]; then
  echo "Unsafe flag ownership, mode, or type." >&2
  exit 1
fi
