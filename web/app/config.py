"""Strict environment-backed configuration for the Web container."""

from __future__ import annotations

import os
from datetime import timedelta


def required_environment(name: str, *, minimum: int = 1) -> str:
    value = os.environ.get(name, "")
    if len(value) < minimum:
        raise RuntimeError(f"required environment variable is missing or too short: {name}")
    return value


class Config:
    SECRET_KEY = required_environment("FLASK_SECRET_KEY", minimum=32)
    DB_HOST = required_environment("DB_HOST")
    DB_NAME = required_environment("DB_NAME")
    DB_USER = required_environment("DB_USER")
    DB_PASSWORD = required_environment("DB_PASSWORD", minimum=16)

    MAX_CONTENT_LENGTH = 16 * 1024
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_PATH = "/"

    RESULT_DIRECTORY = "/tmp/relayforge-results"
    MAX_RESULT_BYTES = 64 * 1024

