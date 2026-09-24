"""Calls to the deliberately narrow relay_web PostgreSQL API."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import psycopg2
import psycopg2.extras
from flask import current_app


def connect():
    return psycopg2.connect(
        host=current_app.config["DB_HOST"],
        dbname=current_app.config["DB_NAME"],
        user=current_app.config["DB_USER"],
        password=current_app.config["DB_PASSWORD"],
        connect_timeout=3,
        application_name="relayforge-web",
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def scalar(statement: str, parameters: Iterable[Any]) -> Any:
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(statement, tuple(parameters))
            row = cursor.fetchone()
            if row is None:
                return None
            return next(iter(row.values()))


def rows(statement: str, parameters: Iterable[Any]) -> list[dict[str, Any]]:
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(statement, tuple(parameters))
            return [dict(row) for row in cursor.fetchall()]


def authenticate(username: str, password: str) -> bool:
    return bool(
        scalar(
            "SELECT relay_web_api.authenticate(%s, %s) AS authenticated",
            (username, password),
        )
    )


def list_targets(username: str) -> list[dict[str, Any]]:
    return rows(
        "SELECT * FROM relay_web_api.list_targets(%s)",
        (username,),
    )


def submit_safe_request(username: str, target: str, service: str, duration: int) -> str:
    request_id = scalar(
        "SELECT relay_web_api.submit_safe_request(%s, %s, %s, %s) AS request_id",
        (username, target, service, duration),
    )
    if request_id is None:
        raise RuntimeError("database returned no request identifier")
    return str(request_id)


def request_status(username: str, request_id: str) -> dict[str, Any] | None:
    result = rows(
        "SELECT * FROM relay_web_api.request_status(%s, %s::uuid)",
        (username, request_id),
    )
    return result[0] if result else None


def cancel_request(username: str, request_id: str) -> bool:
    return bool(
        scalar(
            "SELECT relay_web_api.cancel_request(%s, %s::uuid) AS cancelled",
            (username, request_id),
        )
    )


def submit_raw_request(
    username: str,
    target: str,
    service: str,
    duration: int,
    options_raw: str,
) -> str:
    """Internal pivot available to a process that has compromised this container.

    No HTTP route calls this deliberately retained raw-request RPC.
    """
    request_id = scalar(
        "SELECT relay_web_api.submit_raw_request(%s, %s, %s, %s, %s) AS request_id",
        (username, target, service, duration, options_raw),
    )
    if request_id is None:
        raise RuntimeError("database returned no request identifier")
    return str(request_id)
