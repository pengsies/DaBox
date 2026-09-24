#!/usr/bin/env python3
"""Validate the attacker-side Flask remember-cookie payload builder."""

from __future__ import annotations

import base64
import binascii
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "attacks"))
from pickle_payload import payload, random_result_name, validate_result_name  # noqa: E402


def expect_value_error(callable_object) -> None:
    try:
        callable_object()
    except ValueError:
        return
    raise AssertionError("invalid payload input was accepted")


def main() -> None:
    command = "printf relayforge"
    encoded = payload(command)
    try:
        serialized = base64.b64decode(encoded, validate=True)
    except binascii.Error as exc:
        raise AssertionError("payload is not strict base64") from exc
    assert len(serialized) <= 6144
    for expected in (b"prefs", b"JobTemplate", b"JobRunner", command.encode("ascii")):
        assert expected in serialized

    name = random_result_name()
    validate_result_name(name)
    assert len(name) == 36 and name.endswith(".txt")
    expect_value_error(lambda: payload(""))
    expect_value_error(lambda: payload("bad\x00command"))
    expect_value_error(lambda: validate_result_name("../result.txt"))
    print("PASS: Flask remember-cookie payload encodes the intended restricted gadget pair")


if __name__ == "__main__":
    main()

