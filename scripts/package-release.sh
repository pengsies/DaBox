#!/usr/bin/env bash
set -euo pipefail
umask 077

source_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
release_name=RelayForge-Responsibilities-Flask-v1
output_dir=${1:-$(dirname "$source_root")}

for command_name in rsync shasum unzip zip; do
  command -v "$command_name" >/dev/null || {
    echo "Required packaging command is missing: $command_name" >&2
    exit 69
  }
done
[[ -d $output_dir ]] || {
  echo "Output directory does not exist: $output_dir" >&2
  exit 66
}
output_dir=$(cd "$output_dir" && pwd -P)

if find "$source_root" -type l -print -quit | grep -q .; then
  echo "Refusing to package symbolic links." >&2
  exit 1
fi

build_root=$(mktemp -d /tmp/relayforge-responsibilities-release.XXXXXX)
trap 'rm -rf -- "$build_root"' EXIT INT TERM
stage=$build_root/$release_name
install -d -m 0755 "$stage"

rsync -a \
  --exclude='.git/' \
  --exclude='.DS_Store' \
  --exclude='.env' \
  --exclude='*.key' \
  --exclude='*.p12' \
  --exclude='*.pem' \
  --exclude='*.pfx' \
  --exclude='*.pyc' \
  --exclude='__pycache__/' \
  --exclude='build/' \
  --exclude='dist/' \
  --exclude='relay-worker' \
  --exclude='secrets/' \
  "$source_root/" "$stage/"

if find "$stage" -type f \( -name '*.pem' -o -name '*.key' -o -name '*.p12' \
     -o -name '*.pfx' -o -name '*.pyc' -o -name '.env' -o -name 'relay-worker' \) \
     -print -quit | grep -q .; then
  echo "Release staging contains a forbidden generated or secret file." >&2
  exit 1
fi
if grep -RIlE -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$stage" | grep -q .; then
  echo "Release staging contains private-key material." >&2
  exit 1
fi

(
  cd "$stage"
  find . -type f ! -name MANIFEST.sha256 -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 shasum -a 256 \
    | sed 's#  \./#  #' >MANIFEST.sha256
)
find "$stage" -exec touch -t 202609120000 {} +
(
  cd "$build_root"
  find "$release_name" -print | LC_ALL=C sort \
    | zip -X -q "$build_root/$release_name.zip" -@
)

unzip -t "$build_root/$release_name.zip" >/dev/null
temporary_output=$output_dir/.$release_name.zip.tmp
temporary_checksum=$output_dir/.$release_name.zip.sha256.tmp
install -m 0644 "$build_root/$release_name.zip" "$temporary_output"
shasum -a 256 "$temporary_output" \
  | sed "s#  .*#  $release_name.zip#" >"$temporary_checksum"
mv -f -- "$temporary_output" "$output_dir/$release_name.zip"
mv -f -- "$temporary_checksum" "$output_dir/$release_name.zip.sha256"
chmod 0644 "$output_dir/$release_name.zip.sha256"
printf 'Created %s\n' "$output_dir/$release_name.zip"
cat "$output_dir/$release_name.zip.sha256"
