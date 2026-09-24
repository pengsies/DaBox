#!/usr/bin/env python3
from __future__ import annotations

import os
import stat
import sys
import time
from pathlib import Path


def main() -> int:
    path_value = os.environ.get("HEARTBEAT_FILE")
    if not path_value:
        print("HEARTBEAT_FILE is unset", file=sys.stderr)
        return 1
    try:
        maximum_age = float(os.environ.get("HEARTBEAT_MAX_AGE", "15"))
    except ValueError:
        print("HEARTBEAT_MAX_AGE is invalid", file=sys.stderr)
        return 1
    if not 1 <= maximum_age <= 300:
        print("HEARTBEAT_MAX_AGE is out of range", file=sys.stderr)
        return 1

    try:
        metadata = Path(path_value).stat()
    except OSError as exc:
        print(f"heartbeat unavailable: {exc}", file=sys.stderr)
        return 1
    age = time.time() - metadata.st_mtime
    if not stat.S_ISREG(metadata.st_mode) or age < -5 or age > maximum_age:
        print(f"heartbeat stale or invalid: age={age:.1f}s", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
