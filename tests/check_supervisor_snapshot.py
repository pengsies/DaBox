#!/usr/bin/env python3
"""Check the bounded Supervisor/Worker handoff variant."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    supervisor = (ROOT / "host/supervisor.py").read_text(encoding="utf-8")
    worker = (ROOT / "worker/relay-worker.c").read_text(encoding="utf-8")
    failures: list[str] = []
    required_supervisor = (
        'f"--property=RuntimeMaxSec={max(1, int(active.deadline - time.time()))}s"',
        'set(message) != {"op", "job_id"}',
        'operation == "stop" and peer_uid == supervisor.dispatch_uid',
        "if not self._stop_unit(unit)",
        "time.sleep(ARCHIVE_DELAY_SECONDS)",
    )
    for marker in required_supervisor:
        if marker not in supervisor:
            failures.append(f"Supervisor contract missing: {marker}")
    if "Restart=always" in supervisor or "WORKER_ROTATION_SECONDS" in supervisor:
        failures.append("rotating parent lifecycle leaked into bounded Supervisor")
    for marker in (
        "TOKEN ",
        "CONNECTED\\n",
        "OVERFLOW ",
        "target_host=",
        "target_port=",
        'prefix[] = "/relay/"',
        '"403 Forbidden"',
    ):
        if marker not in worker:
            failures.append(f"Worker contract missing: {marker}")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print("PASS: bounded Supervisor launch/stop/archive and Worker handoff contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
