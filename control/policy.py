from __future__ import annotations

import re
from dataclasses import dataclass


MAX_OPTIONS_BYTES = 512
NOTE_RE = re.compile(r"[a-z0-9._-]{1,32}\Z", re.ASCII)


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedOptions:
    profiles: tuple[str, ...]
    note: str

    @property
    def effective_profile(self) -> str:
        # INTENTIONAL-VULNERABILITY RF-PARSE-01: authorization uses first value.
        return self.profiles[0]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    parsed: ParsedOptions | None = None


def parse_options(raw: str) -> ParsedOptions:
    # Routing never belongs here: target_id resolves to a trusted DB endpoint.
    # This raw string exists only for the profile-parser teaching boundary and
    # a bounded audit note.
    if type(raw) is not str:
        raise PolicyError("options-not-text")
    try:
        encoded = raw.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise PolicyError("options-not-ascii") from exc
    if not encoded or len(encoded) > MAX_OPTIONS_BYTES:
        raise PolicyError("options-size")

    pairs = raw.split("&")
    if len(pairs) not in {2, 3}:
        raise PolicyError("pair-count")

    profiles: list[str] = []
    notes: list[str] = []
    for pair in pairs:
        if not pair or pair.count("=") != 1:
            raise PolicyError("malformed-pair")
        key, value = pair.split("=", 1)
        if key == "profile":
            if value not in {"safe", "legacy"}:
                raise PolicyError("invalid-profile")
            profiles.append(value)
        elif key == "note":
            if NOTE_RE.fullmatch(value) is None:
                raise PolicyError("invalid-note")
            notes.append(value)
        else:
            raise PolicyError("unknown-key")

    if not 1 <= len(profiles) <= 2:
        raise PolicyError("profile-count")
    if len(notes) != 1:
        raise PolicyError("note-count")
    if profiles[0] != "safe":
        raise PolicyError("first-profile-not-safe")
    return ParsedOptions(tuple(profiles), notes[0])


def evaluate_request(
    *,
    options_raw: str,
    grant_allowed: bool,
    target_enabled: bool,
    service: str,
    duration: int,
    max_duration: int,
) -> Decision:
    try:
        parsed = parse_options(options_raw)
    except PolicyError as exc:
        return Decision(False, f"malformed-options:{exc}")
    if not grant_allowed:
        return Decision(False, "grant-denied", parsed)
    if not target_enabled:
        return Decision(False, "target-disabled", parsed)
    if service != "echo":
        return Decision(False, "service-denied", parsed)
    if duration < 30 or duration > max_duration:
        return Decision(False, "duration-denied", parsed)
    if parsed.effective_profile != "safe":
        return Decision(False, "profile-denied", parsed)
    return Decision(True, "policy-allowed", parsed)
