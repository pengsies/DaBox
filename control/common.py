from __future__ import annotations

import logging
import os
from pathlib import Path

import psycopg


LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def configure_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format=LOG_FORMAT,
    )


def _secret(name: str) -> str:
    file_name = os.environ.get(f"{name}_FILE")
    direct = os.environ.get(name)
    if file_name and direct:
        raise RuntimeError(f"set only one of {name} and {name}_FILE")
    if file_name:
        value = Path(file_name).read_text(encoding="utf-8").strip()
    else:
        value = direct or ""
    if not value:
        raise RuntimeError(f"missing secret {name} or {name}_FILE")
    return value


def connect() -> psycopg.Connection:
    """Open a short-lived, transaction-scoped application connection."""
    return psycopg.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ.get("DB_PORT", "5432")),
        dbname=os.environ.get("DB_NAME", "relayforge"),
        user=os.environ["DB_USER"],
        password=_secret("DB_PASSWORD"),
        connect_timeout=5,
        application_name=os.environ.get("SERVICE_NAME", "relayforge-control"),
        options="-c search_path=pg_catalog -c statement_timeout=5000 -c lock_timeout=2000",
    )


def bounded_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be numeric") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def write_heartbeat(path_value: str) -> None:
    """Atomically refresh a health file without placing secrets in it."""
    path = Path(path_value)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text("ok\n", encoding="ascii")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
