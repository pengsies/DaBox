#!/usr/bin/env python3
"""Test-only Unix peer used to exercise the production Dispatcher RPC client."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path


SOCKET = Path("/run/relayforge/supervisor.sock")
TOKEN = "a" * 48


def main() -> int:
    try:
        SOCKET.unlink()
    except FileNotFoundError:
        pass
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(SOCKET))
    os.chmod(SOCKET, 0o660)
    listener.listen(16)
    while True:
        connection, _ = listener.accept()
        with connection:
            data = bytearray()
            while not data.endswith(b"\n") and len(data) <= 8192:
                chunk = connection.recv(2048)
                if not chunk:
                    break
                data.extend(chunk)
            try:
                message = json.loads(bytes(data))
                if (
                    set(message) == {"op", "payload", "signature_hex"}
                    and message["op"] == "launch"
                ):
                    reply = {"ok": True, "port": 25050, "token": TOKEN}
                elif (
                    set(message) == {"op", "job_id"}
                    and message["op"] == "stop"
                    and isinstance(message["job_id"], str)
                ):
                    reply = {"ok": True}
                else:
                    raise ValueError
            except (ValueError, KeyError, json.JSONDecodeError):
                reply = {"error": "bad-test-request", "ok": False}
            connection.sendall(
                json.dumps(reply, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
            )


if __name__ == "__main__":
    raise SystemExit(main())
