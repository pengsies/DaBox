#!/usr/bin/env python3
"""Exercise the real Flask/DB/Access path in disposable containers."""

from __future__ import annotations

import argparse
import http.cookiejar
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key


ROOT = Path(__file__).resolve().parents[1]
BASE = "https://127.0.0.1:8443"
GUEST_USER = "guest"
GUEST_PASSWORD = "guest-relay-2026"
CRAFTED_OPTIONS = "profile=safe&note=quarterly&profile=legacy"
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
CSRF_RE = re.compile(rb'name="csrf_token" value="([A-Za-z0-9_-]+)"')


class IntegrationError(RuntimeError):
    pass


def compose_command(secrets: Path) -> list[str]:
    return [
        "docker", "compose", "-f", str(ROOT / "compose.yaml"),
        "-f", str(ROOT / "tests/compose.integration.yaml"),
        "--env-file", str(ROOT / ".env.example"),
    ]


def run_compose(
    secrets: Path, arguments: list[str], check: bool = True,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["RF_TEST_SECRETS"] = str(secrets)
    return subprocess.run(
        [*compose_command(secrets), *arguments], cwd=ROOT, env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=30, check=check,
    )


def sql(
    secrets: Path, statement: str, check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return run_compose(
        secrets,
        [
            "exec", "-T", "postgres", "psql", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", "relayforge", "-At", "-F", "\t",
            "-c", statement,
        ],
        check=check,
    )


def opener() -> tuple[urllib.request.OpenerDirector, http.cookiejar.CookieJar]:
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
    )
    return client, jar


def request(
    client: urllib.request.OpenerDirector,
    request_or_url: str | urllib.request.Request,
    timeout: float = 8.0,
) -> tuple[int, bytes, str]:
    try:
        with client.open(request_or_url, timeout=timeout) as response:
            return response.status, response.read(), response.geturl()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.geturl()


def csrf_from(page: bytes) -> str:
    matched = CSRF_RE.search(page)
    if matched is None:
        raise IntegrationError("page did not contain a CSRF token")
    return matched.group(1).decode("ascii")


def login(
    client: urllib.request.OpenerDirector,
    jar: http.cookiejar.CookieJar,
) -> str:
    status, page, _ = request(client, BASE + "/login")
    if status != 200:
        raise IntegrationError(f"login page returned HTTP {status}")
    data = urllib.parse.urlencode(
        {
            "username": GUEST_USER,
            "password": GUEST_PASSWORD,
            "csrf_token": csrf_from(page),
        }
    ).encode("ascii")
    status, dashboard, final_url = request(
        client,
        urllib.request.Request(
            BASE + "/login", data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ),
    )
    if (
        status != 200
        or urllib.parse.urlsplit(final_url).path != "/dashboard"
        or b"YOUR DASHBOARD" not in dashboard
    ):
        raise IntegrationError("guest login did not reach the dashboard")

    cookies = {cookie.name: cookie for cookie in jar}
    if not {"session", "remember_prefs"}.issubset(cookies):
        raise IntegrationError("login did not set both signed-session and remember cookies")
    for name in ("session", "remember_prefs"):
        cookie = cookies[name]
        attributes = {key.lower() for key in cookie._rest}
        if not cookie.secure or "httponly" not in attributes:
            raise IntegrationError(f"{name} cookie lacks Secure/HttpOnly")
    return csrf_from(dashboard)


def post_json(
    client: urllib.request.OpenerDirector,
    path: str,
    value: dict[str, object],
    csrf: str,
) -> tuple[int, dict[str, object]]:
    status, raw, _ = request(
        client,
        urllib.request.Request(
            BASE + path,
            data=json.dumps(value, separators=(",", ":")).encode("ascii"),
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
        ),
    )
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IntegrationError(f"{path} returned non-JSON HTTP {status}") from exc
    if not isinstance(decoded, dict):
        raise IntegrationError(f"{path} returned a non-object JSON response")
    return status, decoded


def get_json(
    client: urllib.request.OpenerDirector, path: str,
) -> tuple[int, dict[str, object]]:
    status, raw, _ = request(client, BASE + path)
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IntegrationError(f"{path} returned non-JSON HTTP {status}") from exc
    if not isinstance(decoded, dict):
        raise IntegrationError(f"{path} returned a non-object JSON response")
    return status, decoded


def wait_state(
    client: urllib.request.OpenerDirector, request_id: str, wanted: str,
) -> dict[str, object]:
    deadline = time.monotonic() + 20
    latest: dict[str, object] = {}
    while time.monotonic() < deadline:
        status, latest = get_json(client, f"/api/status/{request_id}")
        if status != 200:
            raise IntegrationError(f"status route returned HTTP {status}: {latest}")
        if latest.get("request_state") == "denied":
            if wanted == "denied":
                return latest
            raise IntegrationError(
                f"request unexpectedly denied: {latest.get('request_reason')}"
            )
        if latest.get("job_state") == wanted:
            return latest
        time.sleep(0.2)
    raise IntegrationError(f"request did not reach {wanted}: {latest}")


def exploit_raw(options: str) -> str:
    completed = subprocess.run(
        [
            sys.executable, str(ROOT / "web/tools/exploit_stage1.py"), BASE,
            "--username", GUEST_USER, "--password", GUEST_PASSWORD,
            "--insecure", "--raw-options", options,
        ],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=25, check=True,
    )
    matched = UUID_RE.search(completed.stdout)
    if matched is None:
        raise IntegrationError(
            "authenticated pickle gadget did not return a raw-RPC request ID: "
            f"{completed.stdout!r} {completed.stderr!r}"
        )
    return str(uuid.UUID(matched.group(0)))


def submit_raw_sql(secrets: Path, options: str) -> str:
    literal = options.replace("'", "''")
    output = sql(
        secrets,
        "SELECT relay_web_api.submit_raw_request("
        "'guest','archive-echo','echo',420,"
        f"'{literal}');",
    ).stdout.strip()
    matched = UUID_RE.search(output)
    if matched is None:
        raise IntegrationError(f"raw RPC did not return a request ID: {output!r}")
    return str(uuid.UUID(matched.group(0)))


def job_row(secrets: Path, request_id: str) -> tuple[str, str, str]:
    statement = (
        "SELECT r.options_raw,j.payload,encode(j.signature,'hex') "
        "FROM private.requests r JOIN private.jobs j ON j.request_id=r.id "
        f"WHERE r.id='{uuid.UUID(request_id)}'::uuid;"
    )
    output = sql(secrets, statement).stdout.rstrip("\n")
    pieces = output.split("\t")
    if len(pieces) != 3:
        raise IntegrationError(f"unexpected signed-job row: {output!r}")
    return pieces[0], pieces[1], pieces[2]


def target_endpoint(secrets: Path, target_id: str) -> tuple[str, int]:
    escaped_target = target_id.replace("'", "''")
    statement = (
        "SELECT host(endpoint_host),endpoint_port FROM private.targets "
        f"WHERE id='{escaped_target}';"
    )
    output = sql(secrets, statement).stdout.rstrip("\n")
    pieces = output.split("\t")
    if len(pieces) != 2:
        raise IntegrationError(f"unexpected target endpoint row: {output!r}")
    host, port_text = pieces
    try:
        address = ipaddress.IPv4Address(host)
        port = int(port_text)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise IntegrationError(f"invalid target endpoint row: {output!r}") from exc
    if str(address) != host or not 1 <= port <= 65535:
        raise IntegrationError(f"non-canonical target endpoint row: {output!r}")
    return host, port


def verify_job(
    public_key: Ed25519PublicKey,
    row: tuple[str, str, str],
    expected_options: str,
    expected_endpoint: tuple[str, int],
) -> None:
    options, payload_text, signature_hex = row
    if options != expected_options:
        raise IntegrationError(f"stored options changed: {options!r}")
    decoded = json.loads(payload_text)
    canonical = json.dumps(
        decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    if canonical != payload_text or decoded["options_raw"] != expected_options:
        raise IntegrationError("signed payload was not exact canonical JSON")
    if (decoded.get("endpoint_host"), decoded.get("endpoint_port")) != expected_endpoint:
        raise IntegrationError("signed payload did not contain the trusted target endpoint")
    public_key.verify(bytes.fromhex(signature_hex), payload_text.encode("ascii"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secrets", required=True, type=Path)
    args = parser.parse_args()
    try:
        key = load_pem_public_key((args.secrets / "job-signing.pub").read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise IntegrationError("test public key is not Ed25519")
        expected_endpoint = target_endpoint(args.secrets, "archive-echo")

        client, jar = opener()
        csrf = login(client, jar)

        bad_status, bad_body = post_json(
            client, "/api/request",
            {"target": "archive-echo", "service": "echo", "duration": 30},
            "invalid",
        )
        if bad_status != 400 or bad_body.get("error") != "invalid CSRF token":
            raise IntegrationError("public mutation accepted an invalid CSRF token")

        public_status, public_body = post_json(
            client,
            "/api/request",
            {
                "target": "archive-echo", "service": "echo", "duration": 30,
                "options": CRAFTED_OPTIONS,
            },
            csrf,
        )
        if public_status != 202:
            raise IntegrationError(
                f"safe public request returned HTTP {public_status}: {public_body}"
            )
        public_id = str(uuid.UUID(str(public_body["request_id"])))
        wait_state(client, public_id, "ready")
        verify_job(
            key, job_row(args.secrets, public_id), "profile=safe&note=portal",
            expected_endpoint,
        )

        cancel_status, cancel_body = post_json(
            client, "/api/cancel", {"id": public_id}, csrf,
        )
        if cancel_status != 200 or cancel_body != {"stopping": True}:
            raise IntegrationError(
                f"cancellation returned HTTP {cancel_status}: {cancel_body}"
            )
        cancelled = wait_state(client, public_id, "stop-ready")
        if cancelled.get("session_token") is not None:
            raise IntegrationError("cancellation did not hide the session token")

        crafted_id = exploit_raw(CRAFTED_OPTIONS)
        wait_state(client, crafted_id, "ready")
        verify_job(
            key, job_row(args.secrets, crafted_id), CRAFTED_OPTIONS,
            expected_endpoint,
        )

        malformed_id = submit_raw_sql(args.secrets, "profile=safe&note=UPPER")
        denied = wait_state(client, malformed_id, "denied")
        if not str(denied.get("request_reason", "")).startswith("malformed-options:"):
            raise IntegrationError(f"malformed request lacked denial reason: {denied}")
        followup_id = submit_raw_sql(args.secrets, "profile=safe&note=after-denial")
        wait_state(client, followup_id, "ready")

        privileges = sql(
            args.secrets,
            "SELECT has_database_privilege('relay_web','relayforge','TEMP'),"
            "has_schema_privilege('relay_web','private','USAGE'),"
            "has_function_privilege('relay_web','relay_web_api.submit_raw_request(text,text,text,integer,text)','EXECUTE');",
        ).stdout.strip()
        if privileges != "f\tf\tt":
            raise IntegrationError(f"unexpected relay_web privileges: {privileges!r}")
        denied_query = sql(
            args.secrets, "SET ROLE relay_web; SELECT * FROM private.jobs LIMIT 1;",
            check=False,
        )
        if denied_query.returncode == 0:
            raise IntegrationError("relay_web directly read private.jobs")

        outstanding_statement = (
            "SELECT count(*) FROM private.requests r "
            "LEFT JOIN private.jobs j ON j.request_id=r.id "
            "WHERE r.user_id='10000000-0000-4000-8000-000000000001'::uuid AND "
            "(r.state IN ('pending','reviewing') OR "
            "(r.state='approved' AND j.state IN "
            "('ready','dispatching','running','stop-ready','stopping')));"
        )
        outstanding = int(sql(args.secrets, outstanding_statement).stdout.strip())
        for index in range(outstanding, 8):
            result = sql(
                args.secrets,
                "SELECT relay_web_api.submit_raw_request("
                "'guest','archive-echo','echo',30,"
                f"'profile=safe&note=cap{index}');",
            )
            if UUID_RE.search(result.stdout) is None:
                raise IntegrationError("could not fill bounded outstanding queue")
        over_limit = sql(
            args.secrets,
            "SELECT relay_web_api.submit_raw_request("
            "'guest','archive-echo','echo',30,'profile=safe&note=overlimit');",
            check=False,
        )
        if over_limit.returncode == 0 or "too many outstanding requests" not in over_limit.stderr:
            raise IntegrationError("per-principal outstanding-job limit did not fail closed")

        web_id = run_compose(args.secrets, ["ps", "--quiet", "web"]).stdout.strip()
        inspection = subprocess.run(
            ["docker", "inspect", web_id], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=10, check=True,
        ).stdout
        if "docker.sock" in inspection or "job-signing.pem" in inspection:
            raise IntegrationError("web container received a host-control/signing mount")
    except (
        IntegrationError, OSError, ValueError, KeyError, json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"FAIL: container integration: {exc}", file=sys.stderr)
        return 1
    print(
        "PASS: HTTPS→Flask authenticated pickle→raw RPC, safe API, "
        "cancellation, parser differential, and Ed25519 integration"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
