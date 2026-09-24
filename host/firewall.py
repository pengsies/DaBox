#!/usr/bin/env python3
"""Install idempotent host and Docker-aware RelayForge firewall chains."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path


ALLOWED_KEYS = {
    "PLAYER_CIDR",
    "PUBLIC_IFACE",
    "ENDPOINT_HOST",
    "ENDPOINT_PORT",
    "FIREWALL_DEFERRED",
}
KEY_RE = re.compile(r"[A-Z][A-Z0-9_]*\Z", re.ASCII)
IFACE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,15}\Z", re.ASCII)


def read_config(path: Path) -> dict[str, str]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
        raise RuntimeError("firewall config must be a root-owned 0600 regular file")
    result: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        if raw.count("=") != 1:
            raise RuntimeError(f"invalid firewall config line {number}")
        key, value = raw.split("=", 1)
        if KEY_RE.fullmatch(key) is None or key not in ALLOWED_KEYS or key in result or not value:
            raise RuntimeError(f"invalid firewall config key on line {number}")
        result[key] = value
    if set(result) != ALLOWED_KEYS:
        raise RuntimeError("firewall config schema is incomplete")
    return result


class Tables:
    def __init__(self, executable: str) -> None:
        resolved = shutil.which(executable)
        if resolved is None:
            raise RuntimeError(f"{executable} is unavailable")
        self.executable = resolved

    def call(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [self.executable, "-w", "5", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=10,
            check=check,
        )

    def chain(self, name: str) -> None:
        if self.call("-N", name, check=False).returncode not in {0, 1}:
            raise RuntimeError(f"could not create firewall chain {name}")
        self.call("-F", name)

    def append(self, chain: str, *rule: str) -> None:
        self.call("-A", chain, *rule)

    def hook_first(self, parent: str, child: str) -> None:
        while self.call("-C", parent, "-j", child, check=False).returncode == 0:
            self.call("-D", parent, "-j", child)
        self.call("-I", parent, "1", "-j", child)


def endpoint(values: dict[str, str]) -> tuple[str, int]:
    try:
        address = ipaddress.IPv4Address(values["ENDPOINT_HOST"])
    except ipaddress.AddressValueError as exc:
        raise RuntimeError("ENDPOINT_HOST must be IPv4") from exc
    if (
        str(address) != values["ENDPOINT_HOST"]
        or address.is_unspecified
        or address.is_multicast
        or int(address) == 0xFFFFFFFF
    ):
        raise RuntimeError("ENDPOINT_HOST must be a canonical usable unicast IPv4 address")
    try:
        port = int(values["ENDPOINT_PORT"])
    except ValueError as exc:
        raise RuntimeError("ENDPOINT_PORT must be numeric") from exc
    if str(port) != values["ENDPOINT_PORT"] or not 1 <= port <= 65_535:
        raise RuntimeError("ENDPOINT_PORT is out of range or noncanonical")
    return str(address), port


def apply_ipv4(
    player: str,
    public_interface: str,
    endpoint_host: str,
    endpoint_port: int,
) -> None:
    table = Tables("iptables")
    table.chain("RF_INPUT")
    table.append("RF_INPUT", "-i", "lo", "-j", "ACCEPT")
    table.append("RF_INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
    table.append("RF_INPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    # Keep key-only administrative SSH recoverable when a roaming tester's
    # public address changes. AWS may still apply a stable organization/VPN
    # source restriction, but the guest must never strand its own operator.
    table.append("RF_INPUT", "-i", public_interface, "-p", "tcp", "--dport", "22", "-j", "ACCEPT")
    table.append("RF_INPUT", "-i", public_interface, "-s", player, "-p", "tcp", "--dport", "443", "-j", "ACCEPT")
    table.append("RF_INPUT", "-i", public_interface, "-s", player, "-p", "tcp", "--dport", "25000:25099", "-j", "ACCEPT")
    table.append("RF_INPUT", "-j", "DROP")
    table.hook_first("INPUT", "RF_INPUT")

    table.chain("RF_OUTPUT")
    table.append("RF_OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
    table.append(
        "RF_OUTPUT",
        "-m",
        "owner",
        "--uid-owner",
        "relay",
        "-d",
        f"{endpoint_host}/32",
        "-p",
        "tcp",
        "--dport",
        str(endpoint_port),
        "-j",
        "RETURN",
    )
    table.append("RF_OUTPUT", "-m", "owner", "--uid-owner", "relay", "-j", "REJECT", "--reject-with", "icmp-port-unreachable")
    table.append("RF_OUTPUT", "-j", "RETURN")
    table.hook_first("OUTPUT", "RF_OUTPUT")

    # Docker performs DNAT before its user chain. Match the original port and
    # the stable lab bridge name so no other published container is opened.
    table.chain("RF_DOCKER")
    table.append("RF_DOCKER", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
    table.append("RF_DOCKER", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    table.append("RF_DOCKER", "-i", public_interface, "-o", "rf-edge0", "-s", player, "-p", "tcp", "-m", "conntrack", "--ctorigdstport", "443", "-j", "RETURN")
    table.append("RF_DOCKER", "-i", public_interface, "-o", "rf-edge0", "-j", "DROP")
    table.append("RF_DOCKER", "-i", public_interface, "-o", "rf-front0", "-j", "DROP")
    table.append("RF_DOCKER", "-i", public_interface, "-o", "rf-db0", "-j", "DROP")
    table.append("RF_DOCKER", "-i", "rf-edge0", "-o", public_interface, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP")
    table.append("RF_DOCKER", "-i", "rf-front0", "-o", public_interface, "-j", "DROP")
    table.append("RF_DOCKER", "-i", "rf-db0", "-o", public_interface, "-j", "DROP")
    table.append("RF_DOCKER", "-j", "RETURN")
    if table.call("-S", "DOCKER-USER", check=False).returncode != 0:
        raise RuntimeError("Docker DOCKER-USER chain is unavailable")
    table.hook_first("DOCKER-USER", "RF_DOCKER")


def apply_ipv6(public_interface: str) -> None:
    table = Tables("ip6tables")
    table.chain("RF6_INPUT")
    table.append("RF6_INPUT", "-i", "lo", "-j", "ACCEPT")
    table.append("RF6_INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
    table.append("RF6_INPUT", "-p", "ipv6-icmp", "-j", "ACCEPT")
    table.append("RF6_INPUT", "-j", "DROP")
    table.hook_first("INPUT", "RF6_INPUT")

    table.chain("RF6_OUTPUT")
    table.append("RF6_OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
    table.append("RF6_OUTPUT", "-m", "owner", "--uid-owner", "relay", "-j", "REJECT", "--reject-with", "icmp6-port-unreachable")
    table.append("RF6_OUTPUT", "-j", "RETURN")
    table.hook_first("OUTPUT", "RF6_OUTPUT")

    table.chain("RF6_FORWARD")
    table.append("RF6_FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
    table.append("RF6_FORWARD", "-i", public_interface, "-j", "DROP")
    table.append("RF6_FORWARD", "-o", public_interface, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP")
    table.append("RF6_FORWARD", "-j", "RETURN")
    table.hook_first("FORWARD", "RF6_FORWARD")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/etc/relayforge/firewall.env"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("firewall must run as root")
    values = read_config(args.config)
    if values["FIREWALL_DEFERRED"] != "0":
        raise SystemExit("firewall configuration is explicitly deferred")
    try:
        player = str(ipaddress.IPv4Network(values["PLAYER_CIDR"], strict=True))
    except ValueError as exc:
        raise SystemExit(f"CIDRs must be canonical IPv4 networks: {exc}") from exc
    public_interface = values["PUBLIC_IFACE"]
    if IFACE_RE.fullmatch(public_interface) is None or not Path("/sys/class/net", public_interface).exists():
        raise SystemExit("PUBLIC_IFACE is invalid or unavailable")
    try:
        endpoint_host, endpoint_port = endpoint(values)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    apply_ipv4(player, public_interface, endpoint_host, endpoint_port)
    apply_ipv6(public_interface)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
