#!/usr/bin/env python3
"""Fail closed on unsafe or incomplete bounded Flask release ZIPs."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
import zipfile
from pathlib import PurePosixPath


REQUIRED = {
    ".env.example",
    "ATTACK_REPORT.md",
    "PLAYER_ATTACK_GUIDE.md",
    "README.md",
    "CONTRACTS.md",
    "DOCKER_COMPONENTS.md",
    "EC2_RECOVERY_AND_UPGRADE.md",
    "SETUP.md",
    "WEB_REQUIRED.md",
    "compose.yaml",
    "config/nginx.conf",
    "control/access.py",
    "control/Dockerfile",
    "control/dispatcher.py",
    "db/init/001-init.sh",
    "db/init/002-schema.sql.in",
    "scripts/install.sh",
    "scripts/init-challenge.sh",
    "scripts/package-release.sh",
    "scripts/reset-lab.sh",
    "host/supervisor.py",
    "worker/relay-worker.c",
    "attacks/full_chain.py",
    "web/Dockerfile",
    "web/app/__init__.py",
}
FORBIDDEN_SUFFIXES = {".key", ".p12", ".pem", ".pfx", ".pyc"}
PRIVATE_MARKER = re.compile(rb"-----BEGIN [^-\r\n]*PRIVATE KEY-----")
MANIFEST_LINE = re.compile(r"([0-9a-f]{64})  ([^\r\n]+)\Z")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    args = parser.parse_args()
    seen: set[str] = set()
    relative: set[str] = set()
    root: str | None = None
    with zipfile.ZipFile(args.bundle) as archive:
        damaged = archive.testzip()
        if damaged is not None:
            raise SystemExit(f"CRC failure: {damaged}")
        for info in archive.infolist():
            name = info.filename
            if name in seen:
                raise SystemExit(f"duplicate ZIP member: {name}")
            seen.add(name)
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise SystemExit(f"unsafe ZIP path: {name}")
            root = root or path.parts[0]
            if path.parts[0] != root:
                raise SystemExit("ZIP has more than one release root")
            if info.flag_bits & 0x1:
                raise SystemExit(f"encrypted ZIP member: {name}")
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise SystemExit(f"symbolic link in ZIP: {name}")
            if info.is_dir():
                continue
            rel = PurePosixPath(*path.parts[1:]).as_posix()
            relative.add(rel)
            if (
                "__pycache__" in path.parts
                or path.suffix.lower() in FORBIDDEN_SUFFIXES
                or path.name in {".env", "relay-worker"}
                or "secrets" in path.parts
            ):
                raise SystemExit(f"forbidden generated/secret member: {name}")
            data = archive.read(info)
            if PRIVATE_MARKER.search(data):
                raise SystemExit(f"private-key marker in ZIP: {name}")
            if info.CRC != zipfile.crc32(data):
                raise SystemExit(f"CRC mismatch: {name}")
        missing = REQUIRED - relative
        if missing:
            raise SystemExit(f"missing required members: {sorted(missing)}")
        if root is None:
            raise SystemExit("empty ZIP")
        manifest_name = f"{root}/MANIFEST.sha256"
        if manifest_name not in seen:
            raise SystemExit("missing MANIFEST.sha256")
        try:
            manifest = archive.read(manifest_name).decode("ascii").splitlines()
        except UnicodeDecodeError as error:
            raise SystemExit("MANIFEST.sha256 is not ASCII") from error
        expected: dict[str, str] = {}
        for number, line in enumerate(manifest, 1):
            match = MANIFEST_LINE.fullmatch(line)
            if match is None:
                raise SystemExit(f"malformed manifest line {number}")
            digest, member = match.groups()
            member_path = PurePosixPath(member)
            if (
                member_path.is_absolute()
                or ".." in member_path.parts
                or member in expected
                or member == "MANIFEST.sha256"
            ):
                raise SystemExit(f"unsafe or duplicate manifest member: {member}")
            expected[member] = digest
        manifest_members = relative - {"MANIFEST.sha256"}
        if set(expected) != manifest_members:
            missing_from_manifest = manifest_members - set(expected)
            absent_from_zip = set(expected) - manifest_members
            raise SystemExit(
                "manifest coverage mismatch: "
                f"missing={sorted(missing_from_manifest)}, "
                f"absent={sorted(absent_from_zip)}"
            )
        for member, digest in expected.items():
            expected_name = f"{root}/{member}"
            if hashlib.sha256(archive.read(expected_name)).hexdigest() != digest:
                raise SystemExit(f"manifest mismatch: {expected_name}")
    print(f"PASS: safe complete bounded Flask release bundle ({len(relative)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
