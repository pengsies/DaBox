#!/usr/bin/env python3
"""Root broker for signed RelayForge jobs.

The archive pathname reopen in ``archive_file`` is the final intentional flaw.
Everything before that point is deliberately strict so it cannot be used as a
generic root command runner.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import pwd
import grp
import re
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key


LOG = logging.getLogger("relayforge.supervisor")
SOCKET_PATH = Path("/run/relayforge/supervisor.sock")
STATE_ROOT = Path("/var/lib/relayforge/workers")
PUBLIC_KEY_PATH = Path("/etc/relayforge/job-signing.pub")
WORKER_PATH = Path("/opt/relayforge/bin/relay-worker")
PORT_FIRST = 25_000
PORT_LAST = 25_099
BACKLOG = 32
MAX_RPC_BYTES = 16_384
MAX_ARCHIVE_BYTES = 4096
ARCHIVE_DELAY_SECONDS = 0.100
TOKEN_RE = re.compile(r"[0-9a-f]{48}\Z", re.ASCII)
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z", re.ASCII)
NOTE_RE = re.compile(r"[a-z0-9._-]{1,32}\Z", re.ASCII)
TARGET_RE = re.compile(r"[a-z][a-z0-9-]{2,31}\Z", re.ASCII)
UTC_SECONDS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00\Z", re.ASCII)
EXPECTED_JOB_KEYS = {
    "job_id",
    "request_id",
    "user_id",
    "target_id",
    "service",
    "duration",
    "endpoint_host",
    "endpoint_port",
    "options_raw",
    "expires_at",
}
STOP = threading.Event()
RPC_SLOTS = threading.BoundedSemaphore(16)


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class JobEnvelope:
    job_id: str
    request_id: str
    user_id: str
    target_id: str
    service: str
    duration: int
    endpoint_host: str
    endpoint_port: int
    options_raw: str
    expires_at: datetime


@dataclass(frozen=True)
class ActiveJob:
    job_id: str
    unit: str
    port: int
    deadline: float
    run_dir: Path


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON key")
        result[key] = value
    return result


def decode_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("ascii", errors="strict"), object_pairs_hook=_reject_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid JSON") from exc
    if type(value) is not dict:
        raise ProtocolError("JSON request must be an object")
    return value


def _canonical_uuid(value: object) -> str:
    if type(value) is not str:
        raise ProtocolError("UUID must be text")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise ProtocolError("invalid UUID") from exc
    if str(parsed) != value or parsed.version != 4 or parsed.variant != uuid.RFC_4122:
        raise ProtocolError("UUID must be canonical RFC 4122 version 4")
    return value


def _canonical_endpoint_host(value: object) -> str:
    """Accept a signed, canonical IPv4 unicast address (including loopback)."""
    if type(value) is not str:
        raise ProtocolError("endpoint host must be text")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ProtocolError("endpoint host must be IPv4") from exc
    if str(address) != value:
        raise ProtocolError("endpoint host must be canonical IPv4 text")
    if address.is_unspecified or address.is_multicast or int(address) == 0xFFFFFFFF:
        raise ProtocolError("endpoint host is not a usable unicast address")
    return value


def validate_options_shape(raw: object) -> str:
    """Validate the shared grammar without choosing first- or last-key semantics."""
    if type(raw) is not str:
        raise ProtocolError("options must be text")
    try:
        encoded = raw.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ProtocolError("options must be ASCII") from exc
    if not encoded or len(encoded) > 512:
        raise ProtocolError("options length is invalid")
    pairs = raw.split("&")
    if len(pairs) not in {2, 3}:
        raise ProtocolError("options pair count is invalid")
    profiles = 0
    notes = 0
    for pair in pairs:
        if not pair or pair.count("=") != 1:
            raise ProtocolError("malformed option pair")
        key, value = pair.split("=", 1)
        if key == "profile":
            profiles += 1
            if value not in {"safe", "legacy"}:
                raise ProtocolError("unknown profile")
        elif key == "note":
            notes += 1
            if NOTE_RE.fullmatch(value) is None:
                raise ProtocolError("invalid note")
        else:
            raise ProtocolError("unknown option key")
    if not 1 <= profiles <= 2 or notes != 1:
        raise ProtocolError("invalid option multiplicity")
    return raw


def parse_canonical_job(payload_text: object, now: datetime | None = None) -> JobEnvelope:
    if type(payload_text) is not str:
        raise ProtocolError("payload must be text")
    try:
        encoded = payload_text.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ProtocolError("payload must be ASCII") from exc
    if not 1 <= len(encoded) <= 4096:
        raise ProtocolError("payload length is invalid")
    payload = decode_object(encoded)
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    if canonical != payload_text:
        raise ProtocolError("payload is not canonical JSON")
    if set(payload) != EXPECTED_JOB_KEYS:
        raise ProtocolError("payload schema is not exact")

    job_id = _canonical_uuid(payload["job_id"])
    request_id = _canonical_uuid(payload["request_id"])
    user_id = _canonical_uuid(payload["user_id"])
    target_id = payload["target_id"]
    if type(target_id) is not str or TARGET_RE.fullmatch(target_id) is None:
        raise ProtocolError("invalid target identifier")
    if payload["service"] != "echo":
        raise ProtocolError("unknown service")
    duration = payload["duration"]
    if type(duration) is not int or not 30 <= duration <= 420:
        raise ProtocolError("invalid duration")
    endpoint_host = _canonical_endpoint_host(payload["endpoint_host"])
    endpoint_port = payload["endpoint_port"]
    if type(endpoint_port) is not int or not 1 <= endpoint_port <= 65_535:
        raise ProtocolError("invalid endpoint port")
    options_raw = validate_options_shape(payload["options_raw"])
    expiry_text = payload["expires_at"]
    if type(expiry_text) is not str or UTC_SECONDS_RE.fullmatch(expiry_text) is None:
        raise ProtocolError("expiry must be an explicit UTC second")
    try:
        expires_at = datetime.fromisoformat(expiry_text)
    except ValueError as exc:
        raise ProtocolError("invalid expiry") from exc
    current = now or datetime.now(timezone.utc)
    if not current < expires_at <= current + timedelta(seconds=120):
        raise ProtocolError("job envelope is expired or too far in the future")
    return JobEnvelope(
        job_id=job_id,
        request_id=request_id,
        user_id=user_id,
        target_id=target_id,
        service="echo",
        duration=duration,
        endpoint_host=endpoint_host,
        endpoint_port=endpoint_port,
        options_raw=options_raw,
        expires_at=expires_at,
    )


def canonical_response(value: dict[str, object]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii") + b"\n"


class Supervisor:
    def __init__(self) -> None:
        self.dispatch_uid = pwd.getpwnam("relay-dispatch").pw_uid
        self.relay_uid = pwd.getpwnam("relay").pw_uid
        self.ipc_gid = grp.getgrnam("relayforge-ipc").gr_gid
        loaded = load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
        if not isinstance(loaded, Ed25519PublicKey):
            raise RuntimeError("job verification key is not Ed25519")
        self.verify_key = loaded
        self.active: dict[str, ActiveJob] = {}
        self.reserved_ports: set[int] = set()
        self.lock = threading.RLock()

    @staticmethod
    def _unit_for(job_id: str) -> str:
        return f"relay-worker-{job_id}.service"

    @staticmethod
    def _unit_active(unit: str) -> bool:
        try:
            result = subprocess.run(
                ["/usr/bin/systemctl", "is-active", "--quiet", unit],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False
        return result.returncode == 0

    @staticmethod
    def _unit_known(unit: str) -> bool:
        try:
            result = subprocess.run(
                ["/usr/bin/systemctl", "show", "--property=LoadState", "--value", unit],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=3,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False
        return result.returncode == 0 and result.stdout.strip() == "loaded"

    @staticmethod
    def _stop_unit(unit: str) -> bool:
        try:
            result = subprocess.run(
                ["/usr/bin/systemctl", "stop", unit],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=8,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False
        if result.returncode != 0 and Supervisor._unit_known(unit):
            return False
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                state = subprocess.run(
                    ["/usr/bin/systemctl", "show", "--property=ActiveState", "--value", unit],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=3,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return False
            if state.returncode != 0 or state.stdout.strip() in {"", "inactive", "failed"}:
                return True
            time.sleep(0.05)
        return False

    def _choose_port(self) -> int:
        for port in range(PORT_FIRST, PORT_LAST + 1):
            if port in self.reserved_ports:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    probe.bind(("0.0.0.0", port))
                except OSError:
                    continue
            self.reserved_ports.add(port)
            return port
        raise RuntimeError("worker port range exhausted")

    def _write_exclusive(
        self, path: Path, data: bytes, mode: int, uid: int, gid: int
    ) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, mode)
        try:
            os.fchmod(descriptor, mode)
            os.fchown(descriptor, uid, gid)
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _prepare_job(self, job: JobEnvelope, port: int, token: str) -> ActiveJob:
        run_dir = STATE_ROOT / job.job_id
        work_dir = run_dir / "work"
        os.mkdir(run_dir, 0o750)
        os.chown(run_dir, 0, self.ipc_gid)
        os.chmod(run_dir, 0o750)
        os.mkdir(work_dir, 0o700)
        # Set the final mode while root still owns the directory.  The
        # Supervisor deliberately lacks CAP_FOWNER, so chmod after handing
        # ownership to relay would fail inside the hardened systemd unit.
        os.chmod(work_dir, 0o700)
        os.chown(work_dir, self.relay_uid, self.ipc_gid)
        self._write_exclusive(
            work_dir / "current.log",
            b"RelayForge worker starting\n",
            0o600,
            self.relay_uid,
            self.ipc_gid,
        )
        config = (
            f"token={token}\n"
            f"job={job.job_id}\n"
            f"duration={job.duration}\n"
            f"target_host={job.endpoint_host}\n"
            f"target_port={job.endpoint_port}\n"
            f"options={job.options_raw}\n"
        ).encode("ascii")
        self._write_exclusive(
            run_dir / "worker.conf", config, 0o440, 0, self.ipc_gid
        )
        deadline = time.time() + job.duration
        unit = self._unit_for(job.job_id)
        metadata = json.dumps(
            {
                "deadline": deadline,
                "job_id": job.job_id,
                "port": port,
                "unit": unit,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii") + b"\n"
        self._write_exclusive(run_dir / "state.json", metadata, 0o600, 0, 0)
        return ActiveJob(job.job_id, unit, port, deadline, run_dir)

    def _start_worker(self, active: ActiveJob) -> None:
        work_dir = active.run_dir / "work"
        config = active.run_dir / "worker.conf"
        command = [
            "/usr/bin/systemd-run",
            "--quiet",
            "--collect",
            f"--unit={active.unit}",
            "--service-type=exec",
            "--uid=relay",
            "--gid=relayforge-ipc",
            f"--working-directory={work_dir}",
            "--property=NoNewPrivileges=yes",
            "--property=PrivateTmp=yes",
            "--property=PrivateDevices=yes",
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=yes",
            "--property=ProtectClock=yes",
            "--property=ProtectControlGroups=yes",
            "--property=ProtectHostname=yes",
            "--property=ProtectKernelLogs=yes",
            "--property=ProtectKernelModules=yes",
            "--property=ProtectKernelTunables=yes",
            "--property=ProtectProc=invisible",
            "--property=RestrictNamespaces=yes",
            "--property=RestrictRealtime=yes",
            "--property=RestrictSUIDSGID=yes",
            "--property=LockPersonality=yes",
            "--property=MemoryDenyWriteExecute=yes",
            "--property=SystemCallArchitectures=native",
            "--property=RestrictAddressFamilies=AF_INET AF_UNIX",
            "--property=CapabilityBoundingSet=",
            "--property=AmbientCapabilities=",
            "--property=DevicePolicy=closed",
            "--property=UMask=0077",
            "--property=TasksMax=64",
            "--property=MemoryMax=128M",
            "--property=CPUQuota=100%",
            "--property=LimitNOFILE=256",
            "--property=LimitCORE=0",
            "--property=KillMode=mixed",
            "--property=TimeoutStopSec=3s",
            f"--property=RuntimeMaxSec={max(1, int(active.deadline - time.time()))}s",
            f"--property=ReadWritePaths={work_dir}",
            "--property=InaccessiblePaths=/etc/relayforge/secrets /var/lib/relayforge/flag -/var/run/docker.sock",
            "--property=SocketBindDeny=any",
            "--property=SocketBindAllow=tcp:25000-25099",
            os.fspath(WORKER_PATH),
            str(active.port),
            os.fspath(config),
        ]
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("systemd rejected transient Worker")
        ready_path = work_dir / "ready"
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                metadata = ready_path.lstat()
                if (
                    stat.S_ISREG(metadata.st_mode)
                    and metadata.st_uid == self.relay_uid
                    and stat.S_IMODE(metadata.st_mode) == 0o600
                    and ready_path.read_bytes() == b"ready\n"
                    and self._unit_active(active.unit)
                ):
                    return
            except FileNotFoundError:
                pass
            if not self._unit_active(active.unit):
                break
            time.sleep(0.05)
        raise RuntimeError("Worker failed readiness check")

    def _verify_launch(self, message: dict[str, Any]) -> JobEnvelope:
        if set(message) != {"op", "payload", "signature_hex"} or message.get("op") != "launch":
            raise ProtocolError("invalid launch schema")
        payload = message["payload"]
        signature_hex = message["signature_hex"]
        if type(payload) is not str or type(signature_hex) is not str:
            raise ProtocolError("invalid launch types")
        if re.fullmatch(r"[0-9a-f]{128}", signature_hex, re.ASCII) is None:
            raise ProtocolError("invalid signature encoding")
        try:
            self.verify_key.verify(bytes.fromhex(signature_hex), payload.encode("ascii"))
        except (InvalidSignature, UnicodeEncodeError) as exc:
            raise ProtocolError("invalid job signature") from exc
        return parse_canonical_job(payload)

    def launch(self, message: dict[str, Any]) -> dict[str, object]:
        job = self._verify_launch(message)
        with self.lock:
            if job.job_id in self.active or (STATE_ROOT / job.job_id).exists():
                raise ProtocolError("job already exists")
            port = self._choose_port()
            token = secrets.token_hex(24)
            active: ActiveJob | None = None
            try:
                active = self._prepare_job(job, port, token)
                self._start_worker(active)
                self.active[job.job_id] = active
            except Exception:
                retained = False
                if active is not None:
                    if self._stop_unit(active.unit):
                        self._remove_state(active)
                    else:
                        # Never release a port that may still belong to a
                        # transient Worker.  The reaper will retry termination.
                        self.active[job.job_id] = active
                        retained = True
                else:
                    partial = STATE_ROOT / job.job_id
                    try:
                        partial_stat = partial.lstat()
                        if stat.S_ISDIR(partial_stat.st_mode) and partial_stat.st_uid == 0:
                            shutil.rmtree(partial)
                    except FileNotFoundError:
                        pass
                if not retained:
                    self.reserved_ports.discard(port)
                raise
        return {"ok": True, "port": port, "token": token}

    def stop(self, message: dict[str, Any]) -> dict[str, object]:
        if set(message) != {"op", "job_id"} or message.get("op") != "stop":
            raise ProtocolError("invalid stop schema")
        job_id = _canonical_uuid(message.get("job_id"))
        unit = self._unit_for(job_id)
        with self.lock:
            active = self.active.get(job_id)
        # An absent unit is successful: stop is deliberately idempotent.
        if not self._stop_unit(unit):
            raise RuntimeError("Worker unit did not stop")
        with self.lock:
            removed = self.active.pop(job_id, None)
            if removed is not None:
                self.reserved_ports.discard(removed.port)
        state = active or ActiveJob(job_id, unit, PORT_FIRST, 0.0, STATE_ROOT / job_id)
        self._remove_state(state)
        return {"ok": True}

    def _peer_in_job(self, pid: int, unit: str) -> bool:
        try:
            lines = Path(f"/proc/{pid}/cgroup").read_text(
                encoding="ascii", errors="strict"
            ).splitlines()
        except (OSError, UnicodeError):
            return False
        for line in lines:
            parts = line.split(":", 2)
            if len(parts) != 3:
                continue
            if unit in Path(parts[2]).parts:
                return True
        return False

    def archive_file(
        self, message: dict[str, Any], peer_pid: int
    ) -> dict[str, object]:
        if set(message) != {"op", "job_id", "name"} or message.get("op") != "archive":
            raise ProtocolError("invalid archive schema")
        job_id = _canonical_uuid(message.get("job_id"))
        name = message.get("name")
        if type(name) is not str or NAME_RE.fullmatch(name) is None:
            raise ProtocolError("invalid archive name")
        with self.lock:
            active = self.active.get(job_id)
        if (
            active is None
            or active.deadline <= time.time()
            or not self._unit_active(active.unit)
            or not self._peer_in_job(peer_pid, active.unit)
        ):
            raise PermissionError("archive caller is not the active Worker")
        path = active.run_dir / "work" / name
        checked = path.lstat()
        if (
            not stat.S_ISREG(checked.st_mode)
            or checked.st_uid != self.relay_uid
            or checked.st_nlink != 1
            or checked.st_size > MAX_ARCHIVE_BYTES
        ):
            raise ProtocolError("archive source failed validation")

        # INTENTIONAL-VULNERABILITY RF-SUP-01: validation and use do not share
        # an fd. The relay user can replace this checked pathname during the
        # deterministic delay, causing the privileged reopen to follow a link.
        time.sleep(ARCHIVE_DELAY_SECONDS)
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        try:
            used = os.fstat(descriptor)
            if not stat.S_ISREG(used.st_mode) or used.st_size > MAX_ARCHIVE_BYTES:
                raise ProtocolError("archive target is not a bounded regular file")
            data = os.read(descriptor, MAX_ARCHIVE_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(data) > MAX_ARCHIVE_BYTES:
            raise ProtocolError("archive target exceeded limit")
        return {"ok": True, "data_b64": base64.b64encode(data).decode("ascii")}

    def _remove_state(self, active: ActiveJob) -> None:
        try:
            metadata = active.run_dir.lstat()
            if stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0:
                shutil.rmtree(active.run_dir)
        except FileNotFoundError:
            pass

    def reap(self) -> None:
        while not STOP.wait(1.0):
            stale: list[ActiveJob] = []
            with self.lock:
                for active in self.active.values():
                    if active.deadline <= time.time() or not self._unit_active(active.unit):
                        stale.append(active)
            for active in stale:
                if not self._stop_unit(active.unit):
                    continue
                with self.lock:
                    if self.active.get(active.job_id) is not active:
                        continue
                    del self.active[active.job_id]
                    self.reserved_ports.discard(active.port)
                self._remove_state(active)

    def restore(self) -> None:
        STATE_ROOT.mkdir(mode=0o711, parents=True, exist_ok=True)
        os.chown(STATE_ROOT, 0, 0)
        os.chmod(STATE_ROOT, 0o711)
        for entry in os.scandir(STATE_ROOT):
            try:
                job_id = _canonical_uuid(entry.name)
                if not entry.is_dir(follow_symlinks=False):
                    continue
                run_dir = STATE_ROOT / entry.name
                run_stat = run_dir.lstat()
                if run_stat.st_uid != 0 or run_stat.st_mode & 0o022:
                    continue
                raw = (run_dir / "state.json").read_bytes()
                state = decode_object(raw.strip())
                if set(state) != {"deadline", "job_id", "port", "unit"}:
                    continue
                if state["job_id"] != job_id or state["unit"] != self._unit_for(job_id):
                    continue
                if type(state["port"]) is not int or not PORT_FIRST <= state["port"] <= PORT_LAST:
                    continue
                if type(state["deadline"]) not in {int, float}:
                    continue
                active = ActiveJob(
                    job_id, state["unit"], state["port"], float(state["deadline"]), run_dir
                )
                if active.deadline > time.time() and self._unit_active(active.unit):
                    self.active[job_id] = active
                    self.reserved_ports.add(active.port)
                elif self._stop_unit(active.unit):
                    self._remove_state(active)
                else:
                    # Retain ownership when termination cannot be confirmed.
                    self.active[job_id] = active
                    self.reserved_ports.add(active.port)
            except (OSError, ValueError, TypeError):
                LOG.warning("ignored invalid persisted Worker state entry=%r", entry.name)


def _read_request(connection: socket.socket) -> dict[str, Any]:
    connection.settimeout(3.0)
    data = bytearray()
    while b"\n" not in data:
        chunk = connection.recv(min(4096, MAX_RPC_BYTES + 1 - len(data)))
        if not chunk:
            raise ProtocolError("incomplete request")
        data.extend(chunk)
        if len(data) > MAX_RPC_BYTES:
            raise ProtocolError("request exceeded limit")
    line, separator, trailing = bytes(data).partition(b"\n")
    if not separator or trailing:
        raise ProtocolError("invalid request framing")
    return decode_object(line)


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def handle_connection(supervisor: Supervisor, connection: socket.socket) -> None:
    try:
        peer_pid, peer_uid, _peer_gid = _peer_credentials(connection)
        message = _read_request(connection)
        operation = message.get("op")
        if operation == "launch" and peer_uid == supervisor.dispatch_uid:
            reply = supervisor.launch(message)
        elif operation == "stop" and peer_uid == supervisor.dispatch_uid:
            reply = supervisor.stop(message)
        elif operation == "archive" and peer_uid == supervisor.relay_uid:
            reply = supervisor.archive_file(message, peer_pid)
        else:
            raise PermissionError("operation is not allowed for peer")
    except Exception as exc:
        # Keep the client response deliberately generic, but retain an
        # administrator-visible traceback so deployment failures identify the
        # missing path or rejected host operation instead of only its class.
        LOG.exception("RPC rejected: %s", type(exc).__name__)
        reply = {"error": type(exc).__name__, "ok": False}
    try:
        connection.sendall(canonical_response(reply))
    except OSError:
        pass
    finally:
        connection.close()


def handle_bounded(supervisor: Supervisor, connection: socket.socket) -> None:
    try:
        handle_connection(supervisor, connection)
    finally:
        RPC_SLOTS.release()


def _stop(_signum: int, _frame: object) -> None:
    STOP.set()


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    os.umask(0o027)
    supervisor = Supervisor()
    supervisor.restore()
    reaper = threading.Thread(target=supervisor.reap, name="reaper", daemon=True)
    reaper.start()

    SOCKET_PATH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    try:
        existing = SOCKET_PATH.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != 0:
            raise RuntimeError("refusing to replace unexpected Supervisor socket path")
        SOCKET_PATH.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(os.fspath(SOCKET_PATH))
        os.chown(SOCKET_PATH, 0, supervisor.ipc_gid)
        os.chmod(SOCKET_PATH, 0o660)
        listener.listen(BACKLOG)
        listener.settimeout(1.0)
        while not STOP.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            if not RPC_SLOTS.acquire(blocking=False):
                try:
                    connection.sendall(canonical_response({"error": "busy", "ok": False}))
                except OSError:
                    pass
                connection.close()
                continue
            thread = threading.Thread(
                target=handle_bounded,
                args=(supervisor, connection),
                name="rpc",
                daemon=True,
            )
            thread.start()
    finally:
        listener.close()
        try:
            SOCKET_PATH.unlink()
        except FileNotFoundError:
            pass
        STOP.set()
        reaper.join(timeout=3.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
