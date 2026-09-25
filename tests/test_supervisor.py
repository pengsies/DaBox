#!/usr/bin/env python3
"""Test signed-job validation and the production diagnostic execution race."""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "host"))
import supervisor as module  # noqa: E402


def expect_error(callable_object, exception=Exception) -> None:
    try:
        callable_object()
    except exception:
        return
    raise AssertionError("operation unexpectedly succeeded")


def canonical_job() -> str:
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat(timespec="seconds")
    value = {
        "job_id": str(uuid.uuid4()),
        "request_id": str(uuid.uuid4()),
        "user_id": str(uuid.uuid4()),
        "target_id": "archive-echo",
        "service": "echo",
        "duration": 420,
        "endpoint_host": "127.0.0.1",
        "endpoint_port": 80,
        "options_raw": "profile=safe&note=quarterly&profile=legacy",
        "expires_at": expiry,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def test_job_validation() -> None:
    text = canonical_job()
    parsed = module.parse_canonical_job(text)
    assert parsed.options_raw.endswith("profile=legacy") and parsed.duration == 420
    assert parsed.endpoint_host == "127.0.0.1" and parsed.endpoint_port == 80
    module.validate_options_shape("profile=legacy&note=x")
    expect_error(lambda: module.validate_options_shape("profile=safe&note=UPPER"), module.ProtocolError)
    expect_error(lambda: module.decode_object(b'{"op":"x","op":"y"}'), module.ProtocolError)
    expect_error(lambda: module.parse_canonical_job(" " + text), module.ProtocolError)
    value = json.loads(text)
    value["extra"] = True
    extra = json.dumps(value, sort_keys=True, separators=(",", ":"))
    expect_error(lambda: module.parse_canonical_job(extra), module.ProtocolError)
    value.pop("extra")
    value["duration"] = True
    wrong_type = json.dumps(value, sort_keys=True, separators=(",", ":"))
    expect_error(lambda: module.parse_canonical_job(wrong_type), module.ProtocolError)
    value["duration"] = 30
    minimum = json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert module.parse_canonical_job(minimum).duration == 30
    for bad_duration in (29, 421):
        value["duration"] = bad_duration
        invalid = json.dumps(value, sort_keys=True, separators=(",", ":"))
        expect_error(lambda invalid=invalid: module.parse_canonical_job(invalid), module.ProtocolError)

    for invalid_host in (
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "127.000.000.001",
        "::1",
        "endpoint.internal",
    ):
        value = json.loads(text)
        value["endpoint_host"] = invalid_host
        invalid = json.dumps(value, sort_keys=True, separators=(",", ":"))
        expect_error(lambda invalid=invalid: module.parse_canonical_job(invalid), module.ProtocolError)

    for invalid_port in (True, 0, 65_536, "80"):
        value = json.loads(text)
        value["endpoint_port"] = invalid_port
        invalid = json.dumps(value, sort_keys=True, separators=(",", ":"))
        expect_error(lambda invalid=invalid: module.parse_canonical_job(invalid), module.ProtocolError)


def test_worker_config_contains_signed_destination() -> None:
    payload = module.parse_canonical_job(canonical_job())
    with tempfile.TemporaryDirectory(prefix="relayforge-supervisor-config-") as name:
        root = Path(name)
        previous_state_root = module.STATE_ROOT
        previous_chown = module.os.chown
        previous_chmod = module.os.chmod
        module.STATE_ROOT = root
        ownership_events: list[tuple[str, str]] = []
        module.os.chown = lambda path, _uid, _gid: ownership_events.append(("chown", Path(path).name))
        module.os.chmod = lambda path, _mode: ownership_events.append(("chmod", Path(path).name))
        try:
            broker = module.Supervisor.__new__(module.Supervisor)
            broker.ipc_gid = os.getegid()
            broker.relay_uid = os.geteuid()
            written: dict[str, bytes] = {}

            def capture(path: Path, data: bytes, _mode: int, _uid: int, _gid: int) -> None:
                written[path.name] = data

            broker._write_exclusive = capture
            broker._prepare_job(payload, 25_000, "a" * 48)
        finally:
            module.STATE_ROOT = previous_state_root
            module.os.chown = previous_chown
            module.os.chmod = previous_chmod

    assert ownership_events.index(("chmod", "work")) < ownership_events.index(("chown", "work"))

    assert written["worker.conf"] == (
        f"token={'a' * 48}\n"
        f"job={payload.job_id}\n"
        "duration=420\n"
        "target_host=127.0.0.1\n"
        "target_port=80\n"
        "options=profile=safe&note=quarterly&profile=legacy\n"
    ).encode("ascii")


def test_signature_validation() -> None:
    private_key = Ed25519PrivateKey.generate()
    broker = module.Supervisor.__new__(module.Supervisor)
    broker.verify_key = private_key.public_key()
    payload = canonical_job()
    signature = private_key.sign(payload.encode("ascii")).hex()
    message = {"op": "launch", "payload": payload, "signature_hex": signature}
    assert broker._verify_launch(message).job_id == json.loads(payload)["job_id"]

    expect_error(
        lambda: broker._verify_launch({**message, "signature_hex": "00" * 64}),
        module.ProtocolError,
    )
    expect_error(
        lambda: broker._verify_launch({**message, "payload": payload.replace("quarterly", "changed")}),
        module.ProtocolError,
    )
    expect_error(
        lambda: broker._verify_launch({**message, "extra": True}),
        module.ProtocolError,
    )


def _recv_line(client: socket.socket) -> bytes:
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = client.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def test_diagnostic_controls_and_race() -> None:
    with tempfile.TemporaryDirectory(prefix="relayforge-supervisor-") as name:
        root = Path(name)
        run_dir = root / "job"
        work = run_dir / "work"
        work.mkdir(parents=True)
        job_id = str(uuid.uuid4())
        active = module.ActiveJob(
            job_id,
            f"relay-worker-{job_id}.service",
            25000,
            time.time() + 60,
            run_dir,
        )
        broker = module.Supervisor.__new__(module.Supervisor)
        broker.relay_uid = os.geteuid()
        broker.lock = threading.RLock()
        broker.active = {job_id: active}
        broker._unit_active = lambda _unit: True
        broker._peer_in_job = lambda _pid, _unit: True

        request = {"op": "diagnose", "job_id": job_id, "name": "diagnostic.sh"}
        race_path = work / "diagnostic.sh"
        race_path.write_bytes(module.DIAGNOSTIC_SCRIPT)
        race_path.chmod(module.DIAGNOSTIC_MODE)
        swap = work / ".replacement"
        swap.write_bytes(
            b"#!/bin/sh\n"
            b"printf 'replacement-executed uid=%s\\n' \"$(id -u)\"\n"
        )
        swap.chmod(module.DIAGNOSTIC_MODE)

        server, client = socket.socketpair()
        client.settimeout(2)
        failures: list[Exception] = []

        def run_diagnostic() -> None:
            try:
                broker.run_diagnostic(request, os.getpid(), server)
            except Exception as exc:  # surfaced in the main test thread
                failures.append(exc)
            finally:
                server.close()

        thread = threading.Thread(target=run_diagnostic)
        thread.start()
        validated = json.loads(_recv_line(client))
        assert validated == {"ok": True, "state": "validated"}
        os.replace(swap, race_path)
        output = _recv_line(client)
        client.close()
        thread.join(timeout=3)
        assert not thread.is_alive()
        assert failures == []
        assert output == f"replacement-executed uid={os.geteuid()}\n".encode("ascii")

        race_path.write_bytes(module.DIAGNOSTIC_SCRIPT)
        race_path.chmod(0o600)
        server, client = socket.socketpair()
        try:
            expect_error(
                lambda: broker.run_diagnostic(request, os.getpid(), server),
                module.ProtocolError,
            )
        finally:
            server.close()
            client.close()

        race_path.unlink()
        race_path.symlink_to(root / "missing")
        server, client = socket.socketpair()
        try:
            expect_error(
                lambda: broker.run_diagnostic(request, os.getpid(), server),
                OSError,
            )
        finally:
            server.close()
            client.close()
        race_path.unlink()
        race_path.write_bytes(module.DIAGNOSTIC_SCRIPT)
        race_path.chmod(module.DIAGNOSTIC_MODE)
        server, client = socket.socketpair()
        try:
            expect_error(
                lambda: broker.run_diagnostic(
                    {"op": "diagnose", "job_id": job_id, "name": "../root-only.sh"},
                    os.getpid(),
                    server,
                ),
                module.ProtocolError,
            )
            expect_error(
                lambda: broker.run_diagnostic(
                    {**request, "extra": True}, os.getpid(), server
                ),
                module.ProtocolError,
            )
            expect_error(
                lambda: broker.run_diagnostic(
                    {**request, "name": "other.sh"}, os.getpid(), server
                ),
                module.ProtocolError,
            )
        finally:
            server.close()
            client.close()

        broker._peer_in_job = lambda _pid, _unit: False
        server, client = socket.socketpair()
        try:
            expect_error(
                lambda: broker.run_diagnostic(request, os.getpid(), server),
                PermissionError,
            )
        finally:
            server.close()
            client.close()


def test_diagnostic_rejects_unauthorized_kernel_uid() -> None:
    broker = module.Supervisor.__new__(module.Supervisor)
    broker.dispatch_uid = 12001
    broker.relay_uid = 12002
    called = False

    def unexpected_diagnostic(*_arguments: object) -> None:
        nonlocal called
        called = True

    broker.run_diagnostic = unexpected_diagnostic
    previous_credentials = module._peer_credentials
    previous_reader = module._read_request
    module._peer_credentials = lambda _connection: (4321, 12003, 12003)
    module._read_request = lambda _connection: {
        "op": "diagnose",
        "job_id": str(uuid.uuid4()),
        "name": "diagnostic.sh",
    }
    server, client = socket.socketpair()
    client.settimeout(2)
    try:
        module.handle_connection(broker, server)
        reply = json.loads(_recv_line(client))
    finally:
        client.close()
        module._peer_credentials = previous_credentials
        module._read_request = previous_reader
    assert reply == {"error": "PermissionError", "ok": False}
    assert called is False


def test_confirmed_idempotent_stop() -> None:
    with tempfile.TemporaryDirectory(prefix="relayforge-supervisor-stop-") as name:
        job_id = str(uuid.uuid4())
        active = module.ActiveJob(
            job_id,
            f"relay-worker-{job_id}.service",
            25023,
            time.time() + 60,
            Path(name) / job_id,
        )
        broker = module.Supervisor.__new__(module.Supervisor)
        broker.lock = threading.RLock()
        broker.active = {job_id: active}
        broker.reserved_ports = {25023}
        outcomes = iter((False, True, True))
        broker._stop_unit = lambda _unit: next(outcomes)
        removed: list[module.ActiveJob] = []
        broker._remove_state = removed.append
        message = {"op": "stop", "job_id": job_id}

        expect_error(lambda: broker.stop(message), RuntimeError)
        assert broker.active == {job_id: active}
        assert broker.reserved_ports == {25023}
        assert removed == []

        assert broker.stop(message) == {"ok": True}
        assert broker.active == {}
        assert broker.reserved_ports == set()
        assert removed == [active]
        assert broker.stop(message) == {"ok": True}
        expect_error(lambda: broker.stop({**message, "extra": True}), module.ProtocolError)


def main() -> None:
    test_job_validation()
    test_worker_config_contains_signed_destination()
    test_signature_validation()
    test_diagnostic_controls_and_race()
    test_diagnostic_rejects_unauthorized_kernel_uid()
    test_confirmed_idempotent_stop()
    print("PASS: Supervisor launch/stop/diagnose gates hold; root-exec TOCTOU is reachable")


if __name__ == "__main__":
    main()
