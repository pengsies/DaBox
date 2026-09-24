#!/usr/bin/env python3
"""Bounded test-only HTTP endpoint for the RelayForge Worker tunnel."""

from __future__ import annotations

import signal
import socket
import sys
import threading


HOST = "0.0.0.0"
PORT = 19_001
MAX_REQUEST_BYTES = 8_192
HEALTH_BODY = b"RelayForge HTTP endpoint healthy\n"
LANDING_BODY = (
    b'<!doctype html><html lang="en"><head><meta charset="utf-8">'
    b"<title>RelayForge endpoint</title></head><body>"
    b"<h1>RelayForge endpoint reached</h1>"
    b"<p>This is a fake flag: RF{browser_tunnel_success}</p>"
    b"</body></html>\n"
)
STOP = threading.Event()


def response(status: bytes, body: bytes, content_type: bytes = b"text/plain; charset=utf-8") -> bytes:
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


def handle(connection: socket.socket) -> None:
    try:
        connection.settimeout(3)
        request = bytearray()
        while b"\r\n\r\n" not in request and len(request) < MAX_REQUEST_BYTES:
            chunk = connection.recv(min(1_024, MAX_REQUEST_BYTES - len(request)))
            if not chunk:
                break
            request.extend(chunk)
        if request.startswith(b"GET / HTTP/1.1\r\n") and b"\r\n\r\n" in request:
            payload = response(b"200 OK", LANDING_BODY, b"text/html; charset=utf-8")
        elif request.startswith(b"GET /health HTTP/1.1\r\n") and b"\r\n\r\n" in request:
            payload = response(b"200 OK", HEALTH_BODY)
        else:
            payload = response(b"404 Not Found", b"Not Found\n")
        connection.sendall(payload)
    except OSError:
        pass
    finally:
        connection.close()


def stop(_signum: int, _frame: object) -> None:
    STOP.set()


def probe() -> int:
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=3) as client:
            client.sendall(
                b"GET /health HTTP/1.1\r\n"
                b"Host: endpoint.test\r\n"
                b"Connection: close\r\n\r\n"
            )
            client.settimeout(3)
            received = bytearray()
            while True:
                chunk = client.recv(4_096)
                if not chunk:
                    break
                received.extend(chunk)
    except OSError:
        return 1
    header, separator, body = bytes(received).partition(b"\r\n\r\n")
    if separator != b"\r\n\r\n" or not header.startswith(b"HTTP/1.1 200 OK\r\n"):
        return 1
    return 0 if body == HEALTH_BODY else 1


def serve() -> int:
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, PORT))
        listener.listen(16)
        listener.settimeout(0.5)
        while not STOP.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            handle(connection)
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--healthcheck"]:
        raise SystemExit(probe())
    if sys.argv[1:]:
        raise SystemExit("usage: sample_endpoint.py [--healthcheck]")
    raise SystemExit(serve())
