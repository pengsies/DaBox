#!/usr/bin/env python3
"""Delete only RelayForge's fixed Worker-state children during a lab reset."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path


STATE_ROOT = Path("/var/lib/relayforge/workers")


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("cleanup must run as root")
    root = STATE_ROOT.resolve(strict=True)
    if os.fspath(root) != "/var/lib/relayforge/workers":
        raise SystemExit("unexpected Worker state root")
    root_stat = root.lstat()
    if not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != 0:
        raise SystemExit("unsafe Worker state root")
    for entry in os.scandir(root):
        path = root / entry.name
        if entry.is_dir(follow_symlinks=False):
            shutil.rmtree(path)
        else:
            path.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
