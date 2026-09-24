#!/usr/bin/env python3
from __future__ import annotations

import json
import socket
import sys


def main() -> int:
    if len(sys.argv) != 2:
        return 64
    message = json.loads(sys.argv[1])
    encoded = json.dumps(message, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect("/run/relayforge/supervisor.sock")
        client.sendall(encoded)
        response = bytearray()
        while not response.endswith(b"\n"):
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    print(bytes(response).decode("ascii").strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
