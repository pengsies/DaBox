"""Legacy remember-me objects retained for the RelayForge training flaw.

The restricted unpickler looks reassuring but permits two classes whose state
hooks form a command-execution gadget chain. This is intentional lab surface.
"""

from __future__ import annotations

import io
import pickle
import subprocess


class RememberedPrefs:
    def __init__(self, username: str = "") -> None:
        self.username = username


class JobTemplate:
    pending: list[str] = []

    def __setstate__(self, state) -> None:
        self.__dict__.update(state)
        JobTemplate.pending.append(self.command)


class JobRunner:
    def __setstate__(self, state) -> None:
        self.__dict__.update(state)
        if JobTemplate.pending:
            # INTENTIONAL-VULNERABILITY RF-WEB-01: the trusted pickle gadget
            # executes attacker-controlled shell text queued by JobTemplate.
            subprocess.Popen(
                JobTemplate.pending.pop(),
                shell=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )


_ALLOWED = {
    ("prefs", "RememberedPrefs"),
    ("prefs", "JobTemplate"),
    ("prefs", "JobRunner"),
}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str):
        if (module, name) not in _ALLOWED:
            raise pickle.UnpicklingError(f"blocked class: {module}.{name}")
        return super().find_class(module, name)


def loads_restricted(data: bytes):
    return RestrictedUnpickler(io.BytesIO(data)).load()

