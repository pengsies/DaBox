#!/usr/bin/env python3
"""Inspect the live partial integration stack's container trust boundaries."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_NETWORK_SUFFIXES = {
    "postgres": {"db_net"},
    "access": {"db_net"},
    "web": {"db_net", "frontend_net"},
    "edge": {"edge_net", "frontend_net"},
}
EXPECTED_USERS = {
    "postgres": "",
    "access": "65532:65532",
    "web": "65532:65532",
    "edge": "",
}
EXPECTED_CAPS = {
    "postgres": {"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID"},
    "access": set(),
    "web": set(),
    "edge": {"CAP_NET_BIND_SERVICE", "CAP_SETGID", "CAP_SETUID"},
}


def compose(secrets: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
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
            "--env-file",
            str(ROOT / ".env.example"),
            *arguments,
        ],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=True,
    )


def inspect(identifier: str) -> dict:
    output = subprocess.run(
        ["docker", "inspect", identifier],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=True,
    ).stdout
    return json.loads(output)[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secrets", required=True, type=Path)
    args = parser.parse_args()
    try:
        for service, expected_networks in EXPECTED_NETWORK_SUFFIXES.items():
            identifier = compose(args.secrets, "ps", "--quiet", service).stdout.strip()
            if not identifier:
                raise AssertionError(f"{service} is not running")
            data = inspect(identifier)
            host = data["HostConfig"]
            state = data["State"]
            if state.get("Health", {}).get("Status") != "healthy":
                raise AssertionError(f"{service} is not healthy")
            if host["Privileged"] or not host["ReadonlyRootfs"]:
                raise AssertionError(f"{service} lacks privileged/read-only controls")
            if set(host.get("CapDrop") or []) != {"ALL"}:
                raise AssertionError(f"{service} does not drop the default capability set")
            if set(host.get("CapAdd") or []) != EXPECTED_CAPS[service]:
                raise AssertionError(f"{service} has unexpected capabilities: {host.get('CapAdd')}")
            if host.get("PidMode") or host.get("IpcMode", "private") == "host" or host.get("NetworkMode") == "host":
                raise AssertionError(f"{service} shares a host namespace")
            if "no-new-privileges:true" not in (host.get("SecurityOpt") or []):
                raise AssertionError(f"{service} lacks no-new-privileges")
            if not host.get("PidsLimit") or not host.get("Memory"):
                raise AssertionError(f"{service} lacks PID/memory limits")
            if data["Config"].get("User", "") != EXPECTED_USERS[service]:
                raise AssertionError(f"{service} has an unexpected configured user")
            networks = {
                name.removeprefix("relayforge-integration_")
                for name in data["NetworkSettings"]["Networks"]
            }
            if networks != expected_networks:
                raise AssertionError(f"{service} network set changed: {networks}")
            serialized_mounts = json.dumps(data.get("Mounts", []))
            if "docker.sock" in serialized_mounts or '"Destination": "/"' in serialized_mounts:
                raise AssertionError(f"{service} has a host-control mount")
            ports = host.get("PortBindings") or {}
            if service == "edge":
                expected = {"443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8443"}]}
                if ports != expected:
                    raise AssertionError(f"integration edge port binding changed: {ports}")
            elif ports:
                raise AssertionError(f"{service} unexpectedly publishes a port: {ports}")

            image = inspect(data["Image"])
            if image.get("Architecture") != "amd64":
                raise AssertionError(f"{service} image is not AMD64")

        access_id = compose(args.secrets, "ps", "--quiet", "access").stdout.strip()
        outbound = subprocess.run(
            [
                "docker",
                "exec",
                access_id,
                "python3",
                "-c",
                "import socket; socket.create_connection(('1.1.1.1',80),1)",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        if outbound.returncode == 0:
            raise AssertionError("Access escaped its internal-only database network")
    except (AssertionError, OSError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"FAIL: container security: {exc}", file=sys.stderr)
        return 1
    print("PASS: live containers enforce capabilities, namespaces, mounts, resources, networks, and publications")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
