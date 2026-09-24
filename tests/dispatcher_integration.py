#!/usr/bin/env python3
"""Exercise real Dispatcher/DB/Unix framing with an explicitly simulated host reply."""

from __future__ import annotations

import argparse
import os
import subprocess
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def command(secrets: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["RF_TEST_SECRETS"] = str(secrets)
    return subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(ROOT / "compose.yaml"),
            "-f",
            str(ROOT / "tests/compose.integration.yaml"),
            "-f",
            str(ROOT / "tests/compose.dispatcher.yaml"),
            "--env-file",
            str(ROOT / ".env.example"),
            *arguments,
        ],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=check,
    )


def query(secrets: Path, statement: str) -> str:
    return command(
        secrets,
        "exec",
        "-T",
        "postgres",
        "psql",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        "postgres",
        "-d",
        "relayforge",
        "-At",
        "-F",
        "\t",
        "-c",
        statement,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secrets", required=True, type=Path)
    args = parser.parse_args()
    try:
        command(args.secrets, "up", "-d", "--build", "fake-supervisor", "dispatcher")
        # Submit only after the Dispatcher is live so the 60-second signed
        # launch envelope cannot become stale while a test image is built.
        request_id = str(
            uuid.UUID(
                query(
                    args.secrets,
                    "SELECT relay_web_api.submit_safe_request('guest','archive-echo','echo',30);",
                )
            )
        )
        deadline = time.monotonic() + 15
        observed = ""
        job_id = ""
        while time.monotonic() < deadline:
            row = query(
                args.secrets,
                f"SELECT COALESCE(j.id::text,''),COALESCE(j.state,''),COALESCE(j.endpoint_port::text,''),COALESCE(j.session_token,'') FROM private.requests r LEFT JOIN private.jobs j ON j.request_id=r.id WHERE r.id='{request_id}'::uuid;",
            )
            pieces = row.split("\t")
            if len(pieces) == 4 and pieces[0]:
                job_id = str(uuid.UUID(pieces[0]))
                observed = "\t".join(pieces[1:])
            if observed.startswith("running\t"):
                break
            time.sleep(0.2)
        if not job_id:
            raise RuntimeError("Access did not prepare the test job")
        if observed != "running\t25050\t" + "a" * 48:
            raise RuntimeError(f"Dispatcher stored an invalid result: {observed!r}")

        cancelled = query(
            args.secrets,
            f"SELECT relay_web_api.cancel_request('guest','{request_id}'::uuid);",
        )
        if cancelled != "t":
            raise RuntimeError("owner cancellation did not enter the durable stop flow")
        deadline = time.monotonic() + 15
        stopped = ""
        while time.monotonic() < deadline:
            stopped = query(
                args.secrets,
                f"SELECT state,COALESCE(session_token,''),stop_attempts FROM private.jobs WHERE id='{job_id}'::uuid;",
            )
            if stopped.startswith("stopped\t\t"):
                break
            time.sleep(0.2)
        if stopped != "stopped\t\t1":
            raise RuntimeError(f"Dispatcher did not converge cancellation through stop RPC: {stopped!r}")

        dispatcher_id = command(args.secrets, "ps", "--quiet", "dispatcher").stdout.strip()
        inspection = subprocess.run(
            ["docker", "inspect", "--format", "{{.HostConfig.Privileged}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.Binds}}", dispatcher_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
        if not inspection.startswith("false|true|") or "docker.sock" in inspection:
            raise RuntimeError(f"Dispatcher runtime boundary is unsafe: {inspection}")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"FAIL: Dispatcher integration: {exc}")
        return 1
    finally:
        command(args.secrets, "stop", "dispatcher", "fake-supervisor", check=False)
        command(args.secrets, "rm", "-f", "dispatcher", "fake-supervisor", check=False)
    print("PASS: Dispatcher launches and confirms owner cancellation through bounded Unix RPC (host reply simulated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
