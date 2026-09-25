#!/usr/bin/env python3
"""Source-only security contract audit; it never counts tests as evidence."""

from __future__ import annotations

import argparse
import os
import re
import stat
from pathlib import Path


EXPECTED_MARKER_COUNTS = {
    "RF-WEB-01": 1,
    "RF-WEB-02": 1,
    "RF-DB-01": 1,
    "RF-PARSE-01": 1,
    "RF-PARSE-02": 1,
    "RF-WORKER-01": 1,
    "RF-WORKER-02": 1,
    # The root-execution marker belongs to both sides of its trust boundary:
    # the pathname race and the deliberately unrestricted systemd unit.
    "RF-SUP-ROOT-01": 2,
}
PRODUCTION_DIRS = ("web", "control", "db", "worker", "host", "config")
TEXT_SUFFIXES = {".py", ".php", ".sql", ".in", ".c", ".conf", ".service", ".yaml", ".json", ".ini", ".sh", ".txt"}


class Audit:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.failures: list[str] = []

    def fail(self, message: str) -> None:
        self.failures.append(message)

    def read(self, relative: str) -> str:
        path = self.root / relative
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            self.fail(f"missing/unreadable {relative}: {exc}")
            return ""

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.fail(message)

    def production_text(self) -> str:
        chunks: list[str] = []
        for directory in PRODUCTION_DIRS:
            for path in sorted((self.root / directory).rglob("*")):
                if path.is_file() and path.suffix in TEXT_SUFFIXES and path.name != "relay-worker":
                    chunks.append(path.read_text(encoding="utf-8", errors="strict"))
        return "\n".join(chunks)

    def filesystem(self) -> None:
        self.require(self.root.is_dir(), "audit root is not a directory")
        for path in self.root.rglob("*"):
            relative = path.relative_to(self.root)
            if path.is_symlink():
                self.fail(f"source bundle contains symlink: {relative}")
                continue
            mode = path.stat().st_mode
            if mode & 0o022:
                self.fail(f"source entry is group/world writable: {relative}")
            if path.is_file() and (
                path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}
                or path.name in {".env", "id_rsa", "id_ed25519"}
            ):
                self.fail(f"bundle contains a secret-shaped file: {relative}")
            if path.is_file() and path.name != "static_audit.py" and path.stat().st_size <= 2_000_000:
                data = path.read_bytes()
                if b"BEGIN OPENSSH PRIVATE KEY" in data or b"BEGIN PRIVATE KEY" in data:
                    self.fail(f"bundle embeds a private key: {relative}")
        for path in (self.root / "scripts").glob("*.sh"):
            self.require(bool(path.stat().st_mode & stat.S_IXUSR), f"script is not executable: {path.name}")

    def intentional_surface(self) -> None:
        text = self.production_text()
        observed = set(re.findall(r"RF-[A-Z-]+-[0-9]+", text))
        expected = set(EXPECTED_MARKER_COUNTS)
        self.require(observed == expected, f"intentional marker set changed: {sorted(observed)}")
        for marker, count in EXPECTED_MARKER_COUNTS.items():
            self.require(
                text.count(marker) == count,
                f"intentional marker count changed: {marker}",
            )

    def web(self) -> None:
        application = self.read("web/app/__init__.py")
        authentication = self.read("web/app/auth.py")
        database = self.read("web/app/db.py")
        raw_client = self.read("web/app/raw_rpc.py")
        gadgets = self.read("web/prefs.py")
        dockerfile = self.read("web/Dockerfile")
        nginx = self.read("config/nginx.conf")
        public_source = application + authentication
        self.require(
            '@app.post("/api/request")' in application
            and "db.submit_safe_request" in application,
            "public Flask request route does not use the safe RPC",
        )
        self.require(
            '@app.post("/connections")' in application
            and '@app.get("/connections/<request_id>")' in application
            and "_browser_worker_url" in application
            and "script-src 'none'" in nginx
            and "upgrade-insecure-requests" not in nginx,
            "server-rendered browser connection flow is incomplete",
        )
        self.require(
            "submit_raw_request" not in public_source,
            "public Flask route references the raw DB RPC",
        )
        self.require(
            "def submit_raw_request" in database
            and "app.raw_rpc" not in application
            and "submit_raw_request" in raw_client,
            "raw DB RPC is not confined to the post-compromise local client",
        )
        self.require(
            "prefs.loads_restricted" in authentication
            and "@login_required" in application
            and "remember_prefs" in authentication,
            "authenticated remember-cookie deserialization entrypoint changed",
        )
        self.require(
            '("prefs", "JobTemplate")' in gadgets
            and '("prefs", "JobRunner")' in gadgets
            and "subprocess.Popen" in gadgets
            and "shell=True" in gadgets,
            "intended restricted-pickle gadget pair changed",
        )
        self.require(
            "RESULT_RE" in application
            and "O_NOFOLLOW" in application
            and "details.st_uid != os.geteuid()" in application
            and "os.unlink(name, dir_fd=directory_fd)" in application,
            "bounded one-shot result contract changed",
        )
        self.require(
            "validate_csrf()" in application
            and "SESSION_COOKIE_SECURE = True" in self.read("web/app/config.py"),
            "Flask mutation/session gate changed",
        )
        self.require(
            "USER 65532:65532" in dockerfile
            and "gunicorn" in dockerfile
            and "0.0.0.0:8080" in dockerfile,
            "Flask container identity or listener changed",
        )
        self.require(
            "location ^~ /var/cache/" in nginx
            and "location ~ /\\." in nginx
            and "return 404" in nginx,
            "edge does not reject hidden/legacy paths",
        )

    def compose(self) -> None:
        compose = self.read("compose.yaml")
        dockerfiles = self.read("web/Dockerfile") + self.read("control/Dockerfile")
        combined = compose + dockerfiles
        digests = re.findall(r"sha256:[0-9a-f]{64}", combined)
        self.require(
            len(digests) == 4 and len(set(digests)) >= 3,
            "all four container base references are not digest-pinned",
        )
        self.require(compose.count("ports:") == 1, "more than one Compose service publishes ports")
        self.require('"0.0.0.0:443:443"' in compose, "edge HTTPS publication is missing")
        for forbidden in ("docker.sock", "privileged:", "network_mode: host", "pid: host"):
            self.require(forbidden not in compose, f"forbidden Compose escape surface: {forbidden}")
        self.require(compose.count("internal: true") == 2, "frontend/database networks are not both internal")
        self.require("cap_drop:\n    - ALL" in compose, "common container capability drop is missing")
        self.require('restart: "no"' in compose, "Docker restart policy can race the boot firewall")
        self.require("/run/relayforge:/run/relayforge:ro" in compose, "Dispatcher socket mount is not read-only")
        self.require("SIGNING_KEY: /run/secrets/job-signing.pem" in compose, "Access signing-key mount contract changed")
        self.require("HEARTBEAT_FILE:" in compose and "HEALTH_FILE:" not in compose, "healthcheck environment contract is inconsistent")
        self.require(
            'user: "65532:65532"' in compose
            and "FLASK_SECRET_KEY: ${FLASK_SECRET_KEY}" in compose
            and "http://127.0.0.1:8080/healthz" in compose,
            "Flask Compose identity/secret/health contract changed",
        )
        self.require(
            "RELAY_ENDPOINT_HOST: ${RELAY_ENDPOINT_HOST}" in compose
            and "RELAY_ENDPOINT_PORT: ${RELAY_ENDPOINT_PORT}" in compose,
            "deployment-selected endpoint is not passed to database initialization",
        )

    def database(self) -> None:
        sql = self.read("db/init/002-schema.sql.in")
        self.require("NOLOGIN NOSUPERUSER" in sql, "owner role is not non-login/non-superuser")
        self.require(len(re.findall(r"^\s+LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS$", sql, re.MULTILINE)) == 3, "application role restrictions changed")
        self.require("REVOKE ALL ON ALL TABLES IN SCHEMA private" in sql, "private table grants are not revoked")
        self.require("GRANT EXECUTE ON FUNCTION relay_web_api.submit_raw_request" in sql, "intended restricted raw RPC is absent")
        self.require("session_token ~ '^[0-9a-f]{48}$'" in sql, "database token grammar differs from Worker")
        self.require(
            "endpoint_host inet NOT NULL" in sql
            and "family(endpoint_host) = 4 AND masklen(endpoint_host) = 32" in sql
            and "endpoint_port integer NOT NULL CHECK (endpoint_port BETWEEN 1 AND 65535)" in sql,
            "protected target table lacks a bounded canonical IPv4 endpoint",
        )
        self.require(
            "CREATE FUNCTION relay_access_api.policy_context" in sql
            and "SELECT host(t.endpoint_host)" in sql
            and "SELECT t.endpoint_port" in sql,
            "Access policy context does not resolve the protected target endpoint",
        )
        for match in re.finditer(r"SECURITY DEFINER", sql):
            header_end = sql.find("AS $$", match.end())
            self.require(header_end != -1 and "SET search_path = pg_catalog, private, pg_temp" in sql[match.end():header_end], "SECURITY DEFINER function lacks fixed safe search_path")
        self.require("has_database_privilege(v_role, 'relayforge', 'TEMP')" in sql, "database initialization lacks TEMP privilege audit")
        self.require(
            "max_duration BETWEEN 30 AND 420" in sql
            and "duration BETWEEN 30 AND 420" in sql
            and "ends_at = v_now + make_interval(secs => v_duration)" in sql
            and "'infinity'::timestamptz" not in sql,
            "bounded Worker lifetime was replaced by rotating/persistent semantics",
        )
        self.require(
            "CREATE FUNCTION relay_web_api.cancel_request" in sql
            and "CREATE FUNCTION relay_dispatch_api.claim_stop" in sql
            and "CREATE FUNCTION relay_dispatch_api.finish_stop" in sql
            and "'stop-ready', 'stopping'" in sql,
            "durable cancellation state machine is incomplete",
        )

    def host(self) -> None:
        access = self.read("control/access.py")
        supervisor = self.read("host/supervisor.py")
        supervisor_unit = self.read("host/relay-supervisor.service")
        worker = self.read("worker/relay-worker.c")
        makefile = self.read("worker/Makefile")
        firewall = self.read("host/firewall.py")
        install = self.read("scripts/install.sh")
        verifier = self.read("scripts/verify-hardening.sh")
        self.require("SO_PEERCRED" in supervisor and "/proc/{pid}/cgroup" in supervisor, "Supervisor does not bind diagnose RPC to peer/cgroup")
        self.require("Ed25519PublicKey" in supervisor and "verify_key.verify" in supervisor, "Supervisor does not verify Ed25519 jobs")
        self.require("set(message) != {\"op\", \"payload\", \"signature_hex\"}" in supervisor, "launch RPC schema is not exact")
        self.require(
            'set(message) != {"op", "job_id"}' in supervisor
            and 'operation == "stop" and peer_uid == supervisor.dispatch_uid' in supervisor
            and "if not self._stop_unit(unit)" in supervisor,
            "Supervisor stop RPC does not require dispatcher identity and confirmed termination",
        )
        self.require(
            '"endpoint_host": endpoint_host' in access
            and '"endpoint_port": endpoint_port' in access
            and "signature = signing_key.sign(encoded)" in access,
            "Access does not include the DB-resolved endpoint in its signed payload",
        )
        self.require(
            '"endpoint_host",' in supervisor
            and '"endpoint_port",' in supervisor
            and "endpoint_host = _canonical_endpoint_host" in supervisor
            and "not 1 <= endpoint_port <= 65_535" in supervisor,
            "Supervisor does not require and validate the signed endpoint",
        )
        self.require(
            'f"target_host={job.endpoint_host}\\n"' in supervisor
            and 'f"target_port={job.endpoint_port}\\n"' in supervisor,
            "Supervisor does not hand the signed endpoint to the Worker config",
        )
        self.require(
            'set(message) != {"op", "job_id", "name"}' in supervisor
            and 'message.get("op") != "diagnose"' in supervisor
            and 'name != DIAGNOSTIC_NAME' in supervisor
            and 'operation == "diagnose" and peer_uid == supervisor.relay_uid' in supervisor,
            "diagnose RPC schema, fixed name, or kernel-UID gate changed",
        )
        self.require(
            "_peer_in_job(peer_pid, active.unit)" in supervisor,
            "diagnose does not require the caller's exact active Worker cgroup",
        )
        self.require(
            "getattr(os, \"O_NOFOLLOW\", 0)" in supervisor
            and "checked = os.fstat(descriptor)" in supervisor
            and "checked.st_uid != self.relay_uid" in supervisor
            and "checked.st_nlink != 1" in supervisor
            and "stat.S_IMODE(checked.st_mode) != DIAGNOSTIC_MODE" in supervisor
            and "checked.st_size != len(DIAGNOSTIC_SCRIPT)" in supervisor
            and "data != DIAGNOSTIC_SCRIPT" in supervisor,
            "diagnose pre-race script validation changed",
        )
        acknowledgement = 'connection.sendall(canonical_response({"ok": True, "state": "validated"}))'
        delay = "time.sleep(DIAGNOSTIC_DELAY_SECONDS)"
        execution = "process = subprocess.Popen("
        self.require(
            acknowledgement in supervisor
            and delay in supervisor
            and execution in supervisor
            and supervisor.index(acknowledgement) < supervisor.index(delay) < supervisor.index(execution)
            and "[os.fspath(path)]" in supervisor
            and "stdin=connection" in supervisor
            and "stdout=connection" in supervisor
            and "stderr=connection" in supervisor
            and "min(DIAGNOSTIC_MAX_SECONDS, remaining)" in supervisor,
            "documented acknowledged pathname re-execution primitive changed",
        )
        for weakening in (
            "NoNewPrivileges=no",
            "PrivateDevices=no",
            "PrivateIPC=no",
            "PrivateTmp=no",
            "ProtectHome=no",
            "ProtectSystem=no",
            "RestrictNamespaces=no",
            "RestrictSUIDSGID=no",
            "MemoryDenyWriteExecute=no",
            "LockPersonality=no",
        ):
            self.require(
                weakening in supervisor_unit,
                f"unrestricted-root challenge unit no longer declares {weakening}",
            )
        self.require(
            re.search(
                r"^\s*(?:CapabilityBoundingSet|AmbientCapabilities)=",
                supervisor_unit,
                re.MULTILINE,
            ) is None,
            "Supervisor root capability set is unexpectedly bounded",
        )
        self.require("argc != 3" in worker and "usage: relay-worker PORT CONFIG" in worker, "Worker argv contains more than port/config")
        self.require(
            'copy_config_value(stream, "target_host="' in worker
            and 'copy_config_value(stream, "target_port="' in worker
            and "inet_pton(AF_INET, target_host" in worker,
            "Worker does not load and validate its trusted tunnel destination",
        )
        self.require(
            "static int forward_tunnel(int client_fd, int target_fd)" in worker
            and "static int open_target(void)" in worker
            and "connect(target, (struct sockaddr *)&address" in worker
            and 'static const char connected[] = "CONNECTED\\n"' in worker
            and "send_all(descriptors[1U - index]" in worker,
            "Worker CONNECT path is not a bidirectional TCP tunnel",
        )
        self.require(
            'prefix[] = "/relay/"' in worker
            and '"403 Forbidden"' in worker
            and "constant_time_equal(supplied, session_token)" in worker
            and "serve_browser_client" in worker,
            "Worker browser capability path is not token-gated",
        )
        self.require("sizeof(struct debug_frame)" in worker and "requested >" in worker, "Worker overwrite is not structurally bounded")
        self.require("-fstack-protector-strong" in makefile and "-z,relro,-z,now,-z,noexecstack" in makefile and "-fPIE" in makefile, "Worker build hardening changed")
        self.require("DOCKER-USER" in firewall and "--ctorigdstport" in firewall, "firewall is not Docker-DNAT aware")
        self.require(
            'public_interface, "-p", "tcp", "--dport", "22"' in firewall
            and 'public_interface, "-s", admin' not in firewall
            and '"ADMIN_CIDR"' not in firewall
            and "--admin-cidr" not in install,
            "host firewall can source-lock the key-only SSH recovery path",
        )
        self.require(
            "player_cidr=${PLAYER_CIDR:-0.0.0.0/0}" in install,
            "installer does not default the public CTF player surface to all IPv4",
        )
        self.require(
            "--acknowledge-unrestricted-root" in install
            and "acknowledge_unrestricted_root -ne 1" in install
            and "REFUSING INSTALL" in install,
            "installer does not require explicit acknowledgement of unrestricted host root",
        )
        self.require(
            '"--uid-owner"' in firewall
            and '"ENDPOINT_HOST"' in firewall
            and '"ENDPOINT_PORT"' in firewall,
            "relay endpoint egress restriction is missing",
        )
        self.require("--defer-firewall" in install and "verify-hardening.sh" in install, "installer does not fail closed around firewall/verification")
        self.require(
            "--exclude='verify-hardening.sh'" in verifier
            and "-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----" in verifier,
            "runtime private-key scan can match the verifier itself",
        )
        self.require("staging/control" in install and "staging/web" in install and "staging/attacks" not in install, "installer may copy attack tooling into runtime")
        self.require(
            "FLASK_SECRET_KEY" in install
            and "openssl rand -hex 32" in install
            and "line_count -ne 10" in install,
            "installer does not generate and validate the Flask session secret",
        )
        self.require(
            "RuntimeMaxSec={max(1, int(active.deadline - time.time()))}s" in supervisor
            and "Restart=always" not in supervisor
            and "WORKER_ROTATION_SECONDS" not in supervisor,
            "bounded shared Supervisor contains parent-lab rotation behavior",
        )
        self.require(re.search(r"^\s*source\s", install, re.MULTILINE) is None and re.search(r"^\s*\.\s+/", install, re.MULTILINE) is None, "installer sources a root configuration file")

    def tooling(self) -> None:
        full_chain = self.read("attacks/full_chain.py")
        race = self.read("attacks/exploit_supervisor_race.py")
        self.require("PRIVATE_JOBS=DENIED:42501" in full_chain, "full-chain verifier omits DB least-privilege evidence")
        self.require(
            "_run_pickle" in full_chain
            and "remember_prefs" in full_chain
            and "app.raw_rpc" in full_chain
            and "WEB_ID_RE" in full_chain,
            "full-chain verifier does not exercise the Flask pickle-to-raw-RPC pivot",
        )
        self.require(
            "ERR auth" in full_chain
            and "CONNECTED" in full_chain
            and "tunnel target did not return HTTP" in full_chain,
            "full-chain verifier omits Worker negative/tunnel checks",
        )
        self.require("relay could read the root flag directly" in full_chain, "full-chain verifier omits direct-read denial")
        self.require(
            "ROOT_UID_PROOF_RE.search(race_output)" in full_chain
            and "ROOT_FLAG_PROOF_RE.search(race_output)" in full_chain
            and "race_rc != 0 or uid_match is None or flag_match is None" in full_chain,
            "full-chain verifier can report a false-positive root diagnostic race",
        )
        self.require("return 1" in full_chain and "return 1" in race, "attack tooling does not fail closed")
        self.require(
            'acknowledgement.get("ok") is not True' in race
            and 'acknowledgement.get("state") != "validated"' in race
            and "os.replace(replacement_path, race_path)" in race
            and "PROOF_UID_RE.search(transcript)" in race
            and "PROOF_FLAG_RE.search(transcript)" in race,
            "diagnostic exploit does not synchronize, replace atomically, and prove UID 0 plus flag read",
        )

    def run(self) -> int:
        self.filesystem()
        self.intentional_surface()
        self.web()
        self.compose()
        self.database()
        self.host()
        self.tooling()
        if self.failures:
            for failure in self.failures:
                print(f"FAIL: {failure}")
            print(f"Static audit failed with {len(self.failures)} finding(s).")
            return 1
        print("PASS: source-only static security audit (intentional surface and shortcut controls)")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    return Audit(args.root.resolve()).run()


if __name__ == "__main__":
    raise SystemExit(main())
