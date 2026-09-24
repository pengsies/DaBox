#!/usr/bin/env python3
"""Exercise the production Access parser and its fail-closed decisions."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "control"))
from policy import PolicyError, evaluate_request, parse_options  # noqa: E402


def rejected(raw: str) -> None:
    try:
        parse_options(raw)
    except PolicyError:
        return
    raise AssertionError(f"Access parser accepted malformed input: {raw!r}")


def main() -> None:
    safe = parse_options("profile=safe&note=portal")
    assert safe.profiles == ("safe",) and safe.effective_profile == "safe"
    reordered = parse_options("note=portal&profile=safe")
    assert reordered.profiles == ("safe",)
    differential = parse_options("profile=safe&note=quarterly&profile=legacy")
    assert differential.profiles == ("safe", "legacy")
    assert differential.effective_profile == "safe"

    malformed = [
        "",
        "profile=safe",
        "profile=legacy&note=x",
        "profile=safe&note=UPPER",
        "profile=safe&note=x&unknown=y",
        "profile=safe&note=x&note=y",
        "profile=safe&note=x&profile=legacy&extra=y",
        "profile=safe&note=x&profile=legacy&profile=safe",
        "profile=safe&note=" + "a" * 33,
        "profile=safe%26note=x",
        "profile=safe&note=é",
    ]
    for value in malformed:
        rejected(value)
        decision = evaluate_request(
            options_raw=value,
            grant_allowed=True,
            target_enabled=True,
            service="echo",
            duration=30,
            max_duration=420,
        )
        assert decision.allowed is False and decision.reason.startswith("malformed-options:")

    assert not evaluate_request(
        options_raw="profile=safe&note=x",
        grant_allowed=False,
        target_enabled=True,
        service="echo",
        duration=30,
        max_duration=420,
    ).allowed
    assert not evaluate_request(
        options_raw="profile=safe&note=x",
        grant_allowed=True,
        target_enabled=True,
        service="echo",
        duration=421,
        max_duration=420,
    ).allowed
    print("PASS: production Access parser is strict, first-key, and fail-closed")


if __name__ == "__main__":
    main()
