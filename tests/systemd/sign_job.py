#!/usr/bin/env python3
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def main() -> int:
    loaded = load_pem_private_key(Path("/test/job-signing.pem").read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise RuntimeError("test key is not Ed25519")
    job_id = str(uuid.uuid4())
    payload = {
        "job_id": job_id,
        "request_id": str(uuid.uuid4()),
        "user_id": str(uuid.uuid4()),
        "target_id": "archive-echo",
        "service": "echo",
        "duration": 120,
        "endpoint_host": "127.0.0.1",
        "endpoint_port": 19001,
        "options_raw": "profile=safe&note=systemd&profile=legacy",
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat(timespec="seconds"),
    }
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    request = {
        "op": "launch",
        "payload": text,
        "signature_hex": loaded.sign(text.encode("ascii")).hex(),
    }
    print(json.dumps({"job_id": job_id, "request": request}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
