#!/usr/bin/env python3
"""Verify the complete bounded Flask deployment tree before installation."""

from __future__ import annotations

import stat
from pathlib import Path


SHARED = Path(__file__).resolve().parents[1]
REQUIRED = (
    ".env.example",
    "ATTACK_REPORT.md",
    "PLAYER_ATTACK_GUIDE.md",
    "README.md",
    "CONTRACTS.md",
    "DOCKER_COMPONENTS.md",
    "EC2_RECOVERY_AND_UPGRADE.md",
    "SETUP.md",
    "UNRESTRICTED_ROOT_WARNING.md",
    "WEB_REQUIRED.md",
    "compose.yaml",
    "config/nginx.conf",
    "control/Dockerfile",
    "control/access.py",
    "control/dispatcher.py",
    "control/policy.py",
    "db/init/001-init.sh",
    "db/init/002-schema.sql.in",
    "host/supervisor.py",
    "host/relay-supervisor.service",
    "host/relayforge-stack.service",
    "scripts/install.sh",
    "scripts/init-challenge.sh",
    "scripts/package-release.sh",
    "scripts/reset-lab.sh",
    "worker/Makefile",
    "worker/relay-worker.c",
    "web/.dockerignore",
    "web/Dockerfile",
    "web/requirements.txt",
    "web/prefs.py",
    "web/app/__init__.py",
    "web/app/auth.py",
    "web/app/config.py",
    "web/app/db.py",
    "web/app/raw_rpc.py",
    "web/templates/login.html",
    "web/templates/dashboard.html",
    "web/templates/connection.html",
    "web/static/style.css",
    "attacks/full_chain.py",
    "attacks/pickle_payload.py",
    "tests/run-container-integration.sh",
    "tests/run-endpoint-integration.sh",
    "tests/run-vm.sh",
)


def main() -> int:
    failures: list[str] = []
    for relative in REQUIRED:
        path = SHARED / relative
        if path.is_symlink() or not path.is_file():
            failures.append(f"missing or unsafe deployment file: {relative}")

    for path in SHARED.rglob("*"):
        relative = path.relative_to(SHARED)
        if path.is_symlink():
            failures.append(f"unsafe symbolic link: {relative}")
            continue
        if path.stat().st_mode & 0o022:
            failures.append(f"group/world writable entry: {relative}")
        if path.is_file() and (
            "__pycache__" in relative.parts
            or path.suffix == ".pyc"
            or path.name == ".env"
            or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}
        ):
            failures.append(f"generated or secret-shaped entry: {relative}")

    for path in (SHARED / "scripts").glob("*.sh"):
        if not path.stat().st_mode & stat.S_IXUSR:
            failures.append(f"installer/lifecycle script is not executable: {path.name}")

    compose = (SHARED / "compose.yaml").read_text(encoding="utf-8")
    for expected in (
        "context: ./web",
        "context: ./control",
        "./config/nginx.conf",
        "./db/init",
        "FLASK_SECRET_KEY: ${FLASK_SECRET_KEY}",
        '"0.0.0.0:443:443"',
    ):
        if expected not in compose:
            failures.append(f"Compose is missing expected contract: {expected}")
    if "web stuff" in compose or (SHARED / "web stuff").exists():
        failures.append("raw teammate Web material remains inside deployment")

    schema = (SHARED / "db/init/002-schema.sql.in").read_text(encoding="utf-8")
    supervisor = (SHARED / "host/supervisor.py").read_text(encoding="utf-8")
    installer = (SHARED / "scripts/install.sh").read_text(encoding="utf-8")
    if "max_duration BETWEEN 30 AND 420" not in schema or "duration BETWEEN 30 AND 420" not in schema:
        failures.append("bounded 30-420 second database contract changed")
    if "Restart=always" in supervisor or "WORKER_ROTATION_SECONDS" in supervisor:
        failures.append("parent-lab Worker rotation leaked into bounded responsibilities")
    if "--acknowledge-unrestricted-root" not in installer:
        failures.append("unrestricted-root installer acknowledgement is missing")
    for expected in ("cancel_request", "claim_stop", "finish_stop"):
        if expected not in schema:
            failures.append(f"cancellation DB contract missing: {expected}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print(f"PASS: complete bounded Flask integration ({len(REQUIRED)} required files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
