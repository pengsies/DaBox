#!/usr/bin/env python3
"""VM-level attempts to skip intended RelayForge stages.

This test requires a deployed lab and runs only from the documented player
network. It deliberately submits a crafted ``options`` field to the public
route and proves that the resulting Worker remains in safe mode.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import ipaddress
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "attacks"))
import full_chain as chain  # noqa: E402


def opener(verify_tls: bool, cookies: bool) -> urllib.request.OpenerDirector:
    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPSHandler(context=context)]
    if cookies:
        handlers.append(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    return urllib.request.build_opener(*handlers)


def expected_http(client: urllib.request.OpenerDirector, request: str | urllib.request.Request, code: int) -> None:
    try:
        client.open(request, timeout=5).close()
    except urllib.error.HTTPError as exc:
        if exc.code == code:
            return
        raise AssertionError(f"expected HTTP {code}, received {exc.code}") from exc
    raise AssertionError(f"expected HTTP {code}, request succeeded")


def json_post(url: str, value: dict[str, object]) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        data=json.dumps(value, separators=(",", ":")).encode("ascii"),
        headers={"Content-Type": "application/json"},
    )


def connection_blocked(host: str, port: int) -> bool:
    try:
        client = socket.create_connection((host, port), timeout=1.5)
    except OSError:
        return True
    client.close()
    return False


def target_is_loopback(host: str) -> bool:
    """Return true when every address for the test target is host-local."""
    try:
        addresses = {
            ipaddress.ip_address(address[4][0])
            for address in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError):
        return False
    return bool(addresses) and all(address.is_loopback for address in addresses)


def main() -> int:
    parser = argparse.ArgumentParser(description="Exercise deployed RelayForge shortcut denials")
    parser.add_argument("target")
    parser.add_argument("--verify-tls", action="store_true")
    args = parser.parse_args()
    try:
        base, host = chain._target_details(args.target)
        anonymous = opener(args.verify_tls, cookies=False)
        expected_http(anonymous, f"{base}/api/status/{uuid.uuid4()}", 401)
        expected_http(anonymous, f"{base}/api/result/{'0' * 32}.txt", 401)
        expected_http(anonymous, json_post(f"{base}/api/cancel", {"id": str(uuid.uuid4())}), 401)

        authenticated = opener(args.verify_tls, cookies=True)
        login_page, _ = chain._open(authenticated, f"{base}/login", 8.0)
        login_csrf = chain.CSRF_RE.search(login_page)
        if login_csrf is None:
            raise AssertionError("login page omitted CSRF token")
        dashboard, final_url = chain._post_form(
            authenticated,
            f"{base}/login",
            {
                "username": chain.GUEST_USER,
                "password": chain.GUEST_PASSWORD,
                "csrf_token": login_csrf.group(1).decode("ascii"),
            },
            8.0,
        )
        assert urllib.parse.urlsplit(final_url).path == "/dashboard"
        active_csrf = chain.CSRF_RE.search(dashboard)
        if active_csrf is None:
            raise AssertionError("dashboard omitted current CSRF token")
        csrf = active_csrf.group(1).decode("ascii")
        expected_http(authenticated, f"{base}/api/status/{uuid.uuid4()}", 404)
        expected_http(authenticated, f"{base}/api/result?name=../root.txt", 400)
        expected_http(authenticated, f"{base}/var/cache/{'0' * 32}.txt", 404)
        expected_http(
            authenticated,
            json_post(
                f"{base}/api/diagnose",
                {
                    "op": "diagnose",
                    "job_id": str(uuid.uuid4()),
                    "name": "diagnostic.sh",
                },
            ),
            404,
        )
        malformed_cookie = urllib.request.Request(
            f"{base}/dashboard",
            headers={"Cookie": chain._remember_cookie_header(authenticated, "not-base64")},
        )
        malformed_body, malformed_url = chain._open(authenticated, malformed_cookie, 8.0)
        assert urllib.parse.urlsplit(malformed_url).path == "/dashboard"
        assert b"YOUR DASHBOARD" in malformed_body

        safe_request = urllib.request.Request(
            f"{base}/api/request",
            data=urllib.parse.urlencode({
                "target": "archive-echo",
                "service": "echo",
                "duration": "30",
                "csrf_token": csrf,
                # Public options remain ignored by the Flask route.
                "options": chain.CRAFTED_OPTIONS,
            }).encode("ascii"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        raw, _ = chain._open(authenticated, safe_request, 8.0)
        response = json.loads(raw)
        request_id = str(uuid.UUID(response["request_id"]))
        port, token = chain._poll_job(authenticated, base, request_id, 8.0, 45.0)

        with socket.create_connection((host, port), timeout=5) as wrong:
            wrong.sendall(f"TOKEN {chain._wrong_token(token)}\n".encode("ascii"))
            assert chain._recv_line(wrong, 5) == b"ERR auth\n"

        browser_base = f"http://{host}:{port}/relay"
        expected_http(anonymous, f"{browser_base}/", 403)
        expected_http(anonymous, f"{browser_base}/{chain._wrong_token(token)}/", 403)
        browser_body, _ = chain._open(anonymous, f"{browser_base}/{token}/", 8.0)
        assert b"RelayForge endpoint reached" in browser_body
        assert b"RF{browser_tunnel_success}" in browser_body

        with socket.create_connection((host, port), timeout=5) as safe:
            safe.sendall(f"TOKEN {token}\n".encode("ascii"))
            chain._banner_job(chain._recv_line(safe, 5))
            assert chain._recv_line(safe, 5) == b"OK\n"
            safe.sendall(b"LEAK\n")
            assert chain._recv_line(safe, 5) == b"ERR command\n"
            safe.sendall(b"OVERFLOW 136\n")
            assert chain._recv_line(safe, 5) == b"ERR command\n"
            safe.sendall(b"CONNECT\n")
            assert chain._recv_line(safe, 5) == b"CONNECTED\n"
            safe.sendall(b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n")
            tunneled = chain._read_to_eof(safe, 5)
            assert tunneled.startswith((b"HTTP/1.0 ", b"HTTP/1.1 "))

        cancel = urllib.request.Request(
            f"{base}/api/cancel",
            data=json.dumps({"id": request_id}, separators=(",", ":")).encode("ascii"),
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
        )
        cancel_body, _ = chain._open(authenticated, cancel, 8.0)
        assert json.loads(cancel_body) == {"stopping": True}

        stop_deadline = time.monotonic() + 15.0
        while time.monotonic() < stop_deadline and not connection_blocked(host, port):
            time.sleep(0.25)
        assert connection_blocked(host, port), "cancelled Worker port remained reachable"

        local_target = target_is_loopback(host)
        if not local_target:
            for port_number in (5432, 8080, 19001):
                assert connection_blocked(host, port_number), f"internal port {port_number} is externally reachable"
    except (AssertionError, chain.ChainError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"FAIL: negative-path test: {exc}", file=sys.stderr)
        return 1
    suffix = " (external-port checks skipped for loopback target)" if local_target else ""
    print(
        "PASS: unauthenticated, CSRF, public-diagnose, wrong-token, safe-Worker, cache, "
        f"and internal-port shortcuts denied{suffix}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
