#!/usr/bin/env python3
"""Check the generated IPv4 policy without requiring root or netfilter."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("relayforge_firewall", ROOT / "host" / "firewall.py")
assert SPEC is not None and SPEC.loader is not None
FIREWALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIREWALL)


class FakeTables:
    instances: dict[str, "FakeTables"] = {}

    def __init__(self, executable: str) -> None:
        self.rules: list[tuple[str, ...]] = []
        self.instances[executable] = self

    def call(self, *arguments: str, check: bool = True) -> SimpleNamespace:
        del check
        self.rules.append(("CALL", *arguments))
        return SimpleNamespace(returncode=0)

    def chain(self, name: str) -> None:
        self.rules.append(("CHAIN", name))

    def append(self, chain: str, *rule: str) -> None:
        self.rules.append((chain, *rule))

    def hook_first(self, parent: str, child: str) -> None:
        self.rules.append(("HOOK", parent, child))


def main() -> int:
    assert "ADMIN_CIDR" not in FIREWALL.ALLOWED_KEYS
    with mock.patch.object(FIREWALL, "Tables", FakeTables):
        FIREWALL.apply_ipv4(
            "0.0.0.0/0",
            "ens5",
            "127.0.0.1",
            19001,
        )

    rules = FakeTables.instances["iptables"].rules
    ssh = [rule for rule in rules if rule[0] == "RF_INPUT" and "22" in rule]
    assert len(ssh) == 1
    assert ssh[0][1:3] == ("-i", "ens5")
    assert "-s" not in ssh[0]
    assert ssh[0][-2:] == ("-j", "ACCEPT")

    https = [rule for rule in rules if rule[0] == "RF_INPUT" and "443" in rule]
    workers = [rule for rule in rules if rule[0] == "RF_INPUT" and "25000:25099" in rule]
    assert len(https) == 1 and ("-s", "0.0.0.0/0") == https[0][3:5]
    assert len(workers) == 1 and ("-s", "0.0.0.0/0") == workers[0][3:5]
    assert rules.count(("RF_INPUT", "-j", "DROP")) == 1
    print("PASS: key-only SSH and configured player gates permit public IPv4 access")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
