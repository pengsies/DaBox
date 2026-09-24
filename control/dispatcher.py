#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import os
import re
import signal
import socket
import threading

from common import bounded_float, configure_logging, connect, write_heartbeat


LOG = logging.getLogger("relayforge.dispatcher")
STOP = threading.Event()
MAX_REQUEST_BYTES = 8192
MAX_RESPONSE_BYTES = 4096
TOKEN_RE = re.compile(r"[0-9a-f]{48}\Z", re.ASCII)


class SupervisorError(RuntimeError):
    pass


def call_supervisor_message(
    socket_path: str,
    message: dict[str, object],
    timeout: float,
) -> dict[str, object]:
    request = json.dumps(
        message,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii") + b"\n"
    if len(request) > MAX_REQUEST_BYTES:
        raise SupervisorError("supervisor request exceeds limit")

    response = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(socket_path)
        client.sendall(request)
        while b"\n" not in response:
            chunk = client.recv(min(1024, MAX_RESPONSE_BYTES + 1 - len(response)))
            if not chunk:
                raise SupervisorError("supervisor closed without response")
            response.extend(chunk)
            if len(response) > MAX_RESPONSE_BYTES:
                raise SupervisorError("supervisor response exceeds limit")

    line, separator, trailing = bytes(response).partition(b"\n")
    if not separator or trailing.strip():
        raise SupervisorError("supervisor returned malformed framing")
    try:
        reply = json.loads(line.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupervisorError("supervisor returned invalid JSON") from exc
    if not isinstance(reply, dict) or type(reply.get("ok")) is not bool:
        raise SupervisorError("supervisor returned invalid object")
    return reply


def call_supervisor(
    socket_path: str,
    payload: str,
    signature_hex: str,
    timeout: float,
) -> dict[str, object]:
    return call_supervisor_message(
        socket_path,
        {"op": "launch", "payload": payload, "signature_hex": signature_hex},
        timeout,
    )


def stop_supervisor(socket_path: str, job_id: object, timeout: float) -> dict[str, object]:
    return call_supervisor_message(
        socket_path,
        {"op": "stop", "job_id": str(job_id)},
        timeout,
    )


def claim_one() -> tuple[int, tuple[object, ...] | None, tuple[object, ...] | None]:
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT relay_dispatch_api.expire_jobs()")
        expired = int(cursor.fetchone()[0])
        cursor.execute("SELECT * FROM relay_dispatch_api.claim_stop()")
        stopping = cursor.fetchone()
        if stopping is not None:
            return expired, stopping, None
        cursor.execute("SELECT * FROM relay_dispatch_api.claim_job()")
        return expired, None, cursor.fetchone()


def store_result(
    job_id: object,
    ok: bool,
    port: int | None,
    token: str | None,
    reason: str,
) -> bool:
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT relay_dispatch_api.finish_job(
              %s::uuid, %s::boolean, %s::integer, %s::text, %s::text
            )
            """,
            (job_id, ok, port, token, reason[:256]),
        )
        return cursor.fetchone()[0] is True


def store_stop_result(job_id: object, ok: bool, reason: str) -> bool:
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT relay_dispatch_api.finish_stop(%s::uuid,%s::boolean,%s::text)",
            (job_id, ok, reason[:256]),
        )
        return cursor.fetchone()[0] is True


def _error_reason(reply: dict[str, object]) -> str:
    value = reply.get("error")
    if not isinstance(value, str) or not value:
        return "supervisor-rejected"
    printable = re.sub(r"[^A-Za-z0-9_.:-]", "-", value)
    return ("supervisor:" + printable)[:256] or "supervisor-rejected"


def dispatch_one(
    claimed: tuple[object, ...],
    socket_path: str,
    timeout: float,
) -> None:
    job_id, payload, signature_hex = claimed
    try:
        reply = call_supervisor(socket_path, payload, signature_hex, timeout)
        ok = reply["ok"] is True
        if ok:
            port_value = reply.get("port")
            token_value = reply.get("token")
            if type(port_value) is not int or not 25000 <= port_value <= 25099:
                raise SupervisorError("supervisor returned invalid port")
            if not isinstance(token_value, str) or TOKEN_RE.fullmatch(token_value) is None:
                raise SupervisorError("supervisor returned invalid token")
            port = port_value
            token = token_value
            reason = "worker-running"
        else:
            port = None
            token = None
            reason = _error_reason(reply)
    except Exception as exc:
        ok = False
        port = None
        token = None
        reason = ("supervisor-rpc:" + type(exc).__name__)[:256]
        LOG.warning("job=%s supervisor call failed: %s", job_id, type(exc).__name__)

    stored = store_result(job_id, ok, port, token, reason)
    if not stored:
        # Cancellation may win while Supervisor is starting the Worker.  The
        # durable stop-ready DB state will retry this bounded best-effort stop.
        try:
            stop_supervisor(socket_path, job_id, timeout)
        except Exception:
            LOG.warning("job=%s launch lease lost; immediate stop failed", job_id)
        LOG.info("job=%s launch result discarded because lease changed", job_id)
        return
    LOG.info("job=%s state=%s reason=%s", job_id, "running" if ok else "failed", reason)


def stop_one(claimed: tuple[object, ...], socket_path: str, timeout: float) -> None:
    (job_id,) = claimed
    try:
        reply = stop_supervisor(socket_path, job_id, timeout)
        ok = reply.get("ok") is True
        reason = "worker-stopped" if ok else _error_reason(reply)
    except Exception as exc:
        ok = False
        reason = ("supervisor-stop-rpc:" + type(exc).__name__)[:256]
        LOG.warning("job=%s Supervisor stop failed: %s", job_id, type(exc).__name__)
    if not store_stop_result(job_id, ok, reason):
        LOG.warning("job=%s stop lease was lost", job_id)
        return
    LOG.info("job=%s state=%s reason=%s", job_id, "stopped" if ok else "stop-ready", reason)


def _stop(_signum: int, _frame: object) -> None:
    STOP.set()


def main() -> int:
    configure_logging()
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    poll_interval = bounded_float("POLL_INTERVAL", 0.25, 0.05, 5.0)
    error_interval = bounded_float("ERROR_INTERVAL", 1.0, 0.1, 10.0)
    rpc_timeout = bounded_float("RPC_TIMEOUT", 5.0, 0.25, 10.0)
    socket_path = os.environ.get(
        "SUPERVISOR_SOCKET", "/run/relayforge/supervisor.sock"
    )
    heartbeat = os.environ.get(
        "HEARTBEAT_FILE", "/tmp/relayforge-dispatcher.heartbeat"
    )

    while not STOP.is_set():
        try:
            expired, stopping, claimed = claim_one()
            if expired:
                LOG.info("expired_or_recovered_jobs=%d", expired)
            if stopping is not None:
                stop_one(stopping, socket_path, rpc_timeout)
            elif claimed is not None:
                dispatch_one(claimed, socket_path, rpc_timeout)
            write_heartbeat(heartbeat)
            if stopping is None and claimed is None:
                STOP.wait(poll_interval)
        except Exception:
            LOG.exception("dispatcher loop failed")
            STOP.wait(error_interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
