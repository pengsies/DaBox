#!/usr/bin/env python3
"""Verify the bounded Flask integration against its checked-in manifest."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


SHARED = Path(__file__).resolve().parents[1]
MANIFEST = SHARED / "MANIFEST.sha256"
LINE_RE = re.compile(r"([0-9a-f]{64})  ([^\n]+)\Z")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main() -> int:
    failures: list[str] = []
    if not MANIFEST.is_file() or MANIFEST.is_symlink():
        print("FAIL: missing or unsafe MANIFEST.sha256")
        return 1
    expected: dict[str, str] = {}
    for number, line in enumerate(MANIFEST.read_text(encoding="ascii").splitlines(), 1):
        match = LINE_RE.fullmatch(line)
        if match is None:
            failures.append(f"malformed manifest line {number}")
            continue
        checksum, relative = match.groups()
        if relative in expected or relative.startswith("/") or ".." in Path(relative).parts:
            failures.append(f"unsafe or duplicate manifest path: {relative}")
            continue
        expected[relative] = checksum

    actual = {
        path.relative_to(SHARED).as_posix(): path
        for path in SHARED.rglob("*")
        if path.is_file()
        and path != MANIFEST
        and path.name != ".DS_Store"
        and ".git" not in path.relative_to(SHARED).parts
    }
    for missing in sorted(set(expected) - set(actual)):
        failures.append(f"manifest member is missing: {missing}")
    for extra in sorted(set(actual) - set(expected)):
        failures.append(f"file is absent from manifest: {extra}")
    for relative in sorted(set(expected) & set(actual)):
        path = actual[relative]
        if path.is_symlink():
            failures.append(f"manifest member is a symlink: {relative}")
        elif digest(path) != expected[relative]:
            failures.append(f"manifest checksum mismatch: {relative}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print(f"PASS: {len(expected)} bounded Flask integration files match MANIFEST.sha256")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
