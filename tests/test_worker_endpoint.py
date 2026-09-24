#!/usr/bin/env python3
"""Send a real Worker tunnel through the test-only Docker endpoint."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
TEST_DIRS = (HERE, HERE.parent.parent / "self/tests")
for candidate in TEST_DIRS:
    if (candidate / "test_worker.py").is_file():
        sys.path.insert(0, str(candidate))
        break
else:
    raise SystemExit("FAIL: could not locate the focused Worker test helpers")

sys.dont_write_bytecode = True
import test_worker as worker  # noqa: E402


def main() -> int:
    worker.section("Docker endpoint through production Worker")
    subprocess.run(["make", "-C", str(worker.WORKER_DIR), "clean", "all"], check=True)
    try:
        worker.test_safe_worker()
    finally:
        subprocess.run(["make", "-C", str(worker.WORKER_DIR), "clean"], check=False)
    print("PASS: Docker endpoint returned its exact health response through the Worker")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
