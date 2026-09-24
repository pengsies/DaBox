#!/usr/bin/env python3
"""Small bounded HTTP/1.1 endpoint reached through a RelayForge Worker."""

from __future__ import annotations

import logging
import os
import signal
import socket
import threading


LOG = logging.getLogger("relayforge.backend")
STOP = threading.Event()
SLOTS = threading.BoundedSemaphore(32)
MAX_REQUEST_BYTES = 8192
HEALTH_BODY = b"RelayForge HTTP endpoint healthy\n"
LANDING_BODY = (
    b'<!doctype html><html lang="en"><head><meta charset="utf-8">'
    b"<title>RelayForge endpoint</title></head><body>"
    b"<h1>RelayForge endpoint reached</h1>"
    b"<p>This is a fake flag: RF{browser_tunnel_success}</p>"
    b"</body></html>\n"
)


def _response(status: bytes, body: bytes, content_type: bytes = b"text/plain; charset=utf-8") -> bytes:
    return (
        b"HTTP/1.1 "
        + status
        + b"\r\nContent-Type: "
        + content_type
        + b"\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Cache-Control: no-store\r\n"
        + b"X-Content-Type-Options: nosniff\r\n"
        + b"Referrer-Policy: no-referrer\r\n"
        + b"Connection: close\r\n\r\n"
        + body
    )


def _client(connection: socket.socket) -> None:
    try:
        connection.settimeout(3.0)
        data = bytearray()
        while b"\r\n\r\n" not in data and len(data) < MAX_REQUEST_BYTES:
            chunk = connection.recv(min(1024, MAX_REQUEST_BYTES - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if b"\r\n\r\n" not in data:
            connection.sendall(_response(b"400 Bad Request", b"Bad Request\n"))
        elif data.startswith(b"GET / HTTP/1.1\r\n"):
            connection.sendall(_response(b"200 OK", LANDING_BODY, b"text/html; charset=utf-8"))
        elif data.startswith(b"GET /health HTTP/1.1\r\n"):
            connection.sendall(_response(b"200 OK", HEALTH_BODY))
        else:
            connection.sendall(_response(b"404 Not Found", b"Not Found\n"))
    except OSError:
        pass
    finally:
        connection.close()
        SLOTS.release()


def _stop(_signum: int, _frame: object) -> None:
    STOP.set()


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 19001))
        listener.listen(32)
        listener.settimeout(1.0)
        while not STOP.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            if not SLOTS.acquire(blocking=False):
                connection.close()
                continue
            threading.Thread(target=_client, args=(connection,), daemon=True).start()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
