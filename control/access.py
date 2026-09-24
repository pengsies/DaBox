#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import logging
import os
import signal
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from common import bounded_float, configure_logging, connect, write_heartbeat
from policy import evaluate_request


LOG = logging.getLogger("relayforge.access")
STOP = threading.Event()


def canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def load_signing_key() -> Ed25519PrivateKey:
    path_value = os.environ.get("SIGNING_KEY_FILE") or os.environ.get("SIGNING_KEY")
    if not path_value:
        raise RuntimeError("SIGNING_KEY_FILE is unset")
    loaded = load_pem_private_key(Path(path_value).read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise RuntimeError("job signing key is not Ed25519")
    return loaded


def validate_endpoint(host: object, port: object) -> tuple[str, int]:
    """Validate the trusted target returned by the database before signing it."""
    if type(host) is not str:
        raise ValueError("endpoint-host-not-text")
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError as exc:
        raise ValueError("endpoint-host-invalid") from exc
    if str(address) != host:
        raise ValueError("endpoint-host-not-canonical")
    if address.is_unspecified or address.is_multicast or int(address) == 0xFFFFFFFF:
        raise ValueError("endpoint-host-not-unicast")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("endpoint-port-invalid")
    return host, port


def process_one(signing_key: Ed25519PrivateKey) -> bool:
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT * FROM relay_access_api.claim_request()")
        claimed = cursor.fetchone()
        if claimed is None:
            return False

        request_id, user_id, target_id, service, duration, options_raw = claimed
        cursor.execute(
            "SELECT * FROM relay_access_api.policy_context(%s::uuid)",
            (request_id,),
        )
        context = cursor.fetchone()
        endpoint_host_raw: object = None
        endpoint_port_raw: object = None
        if context is None:
            decision_allowed = False
            decision_reason = "policy-context-missing"
        else:
            (
                grant_allowed,
                max_duration,
                target_enabled,
                endpoint_host_raw,
                endpoint_port_raw,
            ) = context
            decision = evaluate_request(
                options_raw=options_raw,
                grant_allowed=bool(grant_allowed),
                target_enabled=bool(target_enabled),
                service=service,
                duration=duration,
                max_duration=max_duration,
            )
            decision_allowed = decision.allowed
            decision_reason = decision.reason

        endpoint_host: str | None = None
        endpoint_port: int | None = None
        if decision_allowed:
            try:
                endpoint_host, endpoint_port = validate_endpoint(
                    endpoint_host_raw,
                    endpoint_port_raw,
                )
            except ValueError as exc:
                decision_allowed = False
                decision_reason = f"invalid-endpoint:{exc}"

        job_id: uuid.UUID | None = None
        payload_text: str | None = None
        signature: bytes | None = None
        launch_expires_at: datetime | None = None
        if decision_allowed:
            job_id = uuid.uuid4()
            launch_expires_at = datetime.now(timezone.utc) + timedelta(seconds=60)
            payload = {
                "job_id": str(job_id),
                "request_id": str(request_id),
                "user_id": str(user_id),
                "target_id": target_id,
                "service": service,
                "duration": duration,
                "options_raw": options_raw,
                "endpoint_host": endpoint_host,
                "endpoint_port": endpoint_port,
                "expires_at": launch_expires_at.isoformat(timespec="seconds"),
            }
            encoded = canonical(payload)
            payload_text = encoded.decode("ascii")
            signature = signing_key.sign(encoded)

        cursor.execute(
            """
            SELECT relay_access_api.finish_request(
              %s::uuid, %s::boolean, %s::text, %s::uuid,
              %s::text, %s::bytea, %s::timestamptz
            )
            """,
            (
                request_id,
                decision_allowed,
                decision_reason,
                job_id,
                payload_text,
                signature,
                launch_expires_at,
            ),
        )
        if cursor.fetchone()[0] is not True:
            raise RuntimeError("request lease was lost before completion")
        LOG.info(
            "request=%s decision=%s reason=%s",
            request_id,
            "approved" if decision_allowed else "denied",
            decision_reason,
        )
        return True


def _stop(_signum: int, _frame: object) -> None:
    STOP.set()


def main() -> int:
    configure_logging()
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    poll_interval = bounded_float("POLL_INTERVAL", 0.25, 0.05, 5.0)
    error_interval = bounded_float("ERROR_INTERVAL", 1.0, 0.1, 10.0)
    heartbeat = os.environ.get(
        "HEARTBEAT_FILE", "/tmp/relayforge-access.heartbeat"
    )
    signing_key = load_signing_key()

    while not STOP.is_set():
        try:
            processed = process_one(signing_key)
            write_heartbeat(heartbeat)
            if not processed:
                STOP.wait(poll_interval)
        except Exception:
            LOG.exception("access loop failed")
            STOP.wait(error_interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
