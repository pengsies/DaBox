# Supervisor integration

## Status

The authoritative Supervisor implements four design elements required by the
integrated RelayForge path:

- kernel-verified Unix-socket peer credentials;
- Ed25519 verification of Access-created jobs;
- transient, unprivileged systemd Workers; and
- the intentionally vulnerable diagnostic pathname re-execution used by the
  final host-root race.

This directory is authoritative for the bounded-lifetime, unrestricted-root
Flask challenge. A standalone C Supervisor, permanent Worker, rotation timers,
or alternate manual wire protocol is not a deployment input.

## Authoritative files

| File | Purpose |
|---|---|
| `host/supervisor.py` | Signed-job broker, transient-Worker lifecycle, active-cgroup diagnostic gate, and intentional root-exec TOCTOU. |
| `host/relay-supervisor.service` | Deliberately unrestricted root broker and runtime socket directory for this dangerous challenge variant. |
| `host/STAGE_2_WORKER.txt` | Read-only breadcrumb for the compromised host `relay` Worker. |
| `host/STAGE_3_ROOT.txt` | Root-only breadcrumb proving the final host privilege domain. |
| `tests/test_supervisor.py` | Component coverage for canonical jobs, signatures, exact Worker configuration, diagnostic gates, and the race primitive. |
| `tests/test_systemd_units.sh` | Ubuntu systemd validation for the integrated units. |
| `tests/supervisor_systemd_integration.py` | Real signed Supervisor to transient Worker, tunnel, Worker exploit, cgroup gate, and root diagnostic-race test. |

## Non-negotiable integration boundary

- Dispatcher sends one strict-ASCII JSON object followed by one newline to
  `/run/relayforge/supervisor.sock` as `relay-dispatch`.
- Dispatcher may also send an exact `stop` object containing the canonical job
  UUID. Supervisor releases state and the port only after confirmed unit stop.
- The socket is `root:relayforge-ipc` mode `0660`.
- The verification key is a PEM Ed25519 public key at
  `/etc/relayforge/job-signing.pub`; Access alone receives the private key.
- The launch object has exactly `op`, `payload`, and `signature_hex`. The
  payload must be exact canonical JSON, have the ten documented fields, carry
  a valid signature, and have a current bounded expiry.
- `worker.conf` is `root:relayforge-ipc` mode `0440` and contains exactly six
  ordered lines: token, job, duration, target host, target port, and options.
- The existing `/opt/relayforge/bin/relay-worker` runs as
  `relay:relayforge-ipc` with `<job>/work` as its working directory. Its only
  arguments are the player-facing port and configuration path.
- Readiness is `<job>/work/ready`, owned by `relay`, mode `0600`, with exact
  contents `ready\n`.
- Diagnose accepts only the `relay` UID from the exact active Worker cgroup for
  that job and the exact filename `diagnostic.sh`. It validates one fixed mode
  `0700` benign script, acknowledges validation, waits 250 ms, and executes the
  pathname again as unrestricted host root with the socket as standard I/O.
- The Supervisor is intentionally not systemd-sandboxed in this variant. This
  is the selected final-stage behavior, not a production recommendation.
  `CapabilityBoundingSet=~` resets its bounding set to every capability the
  host kernel supports, and verification checks the live process's permitted,
  effective, and bounding masks rather than trusting the unit text alone.
- `RuntimeDirectoryPreserve=yes` keeps the Supervisor socket directory's inode
  stable across restarts for the Dispatcher's read-only bind mount.
- Stage 2 is installed `root:relayforge-ipc` mode `0440`; Stage 3 is
  `root:root` mode `0400`. Neither marker is a scoring secret.

Because `relay` and host `relay-dispatch` both use `relayforge-ipc` as their
primary group, either host identity can technically read Stage 2. In the
deployed topology Dispatcher runs inside a container and the host marker
directory is not mounted there. Stage 2 is therefore a learning breadcrumb,
not an authorization mechanism. Stage 3 and the scoring flag remain host
root-only; container UID 0 is not equivalent to this host-root stage.

See `../CONTRACTS.md` for the complete integration contract.

## Installed host footprint and upgrade cleanup

The exact `/opt/relayforge/runtime` allowlist is:

```text
backend.py
cleanup_state.py
configure-firewall.sh
firewall.py
harden-ssh.sh
init-challenge.sh
reset-lab.sh
supervisor.py
verify-hardening.sh
```

`/opt/relayforge/bin` contains only `relay-worker`. The systemd unit files are
installed under `/etc/systemd/system`; source documentation, tests, and attack
helpers are not copied to the runtime tree.

During upgrade, `install.sh` removes only the five exact obsolete units
`relay-cleanup.service`, `relay-cleanup.timer`, `relay-rotate.service`,
`relay-rotate.timer`, and permanent `relay-worker.service`. It deliberately
does not wildcard-match current transient `relay-worker-<UUID>.service` units.
The exact historical bounded-root `relay-supervisor.service.d/override.conf`
is also removed; unknown or additional drop-ins fail closed.
Delete-on-reconcile is scoped to the root-owned
`/opt/relayforge/{app,runtime,bin}` directories. Generated secrets, database
volumes, Worker/challenge state, unrelated containers, images, packages, home
files, and `/tmp` contents are not broadly pruned.

## Verification sequence

Run from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_supervisor.py
PYTHONDONTWRITEBYTECODE=1 python3 tests/static_audit.py
tests/run-local.sh
tests/test_systemd_units.sh
tests/run-container-integration.sh
python3 tests/supervisor_systemd_integration.py
```

`run-container-integration.sh` uses a fake Supervisor to isolate the
Access/Dispatcher database path. `supervisor_systemd_integration.py` is the
disposable-container proof for the real Supervisor and Worker on a native
AMD64 Docker engine; it skips ARM-host emulation. Only a clean Ubuntu VM
installation followed by `tests/run-vm.sh` proves the complete
Access-to-unrestricted-root path with the real firewall and network.

## Final deployment inputs

The VM run still requires `PUBLIC_IFACE`, `ADMIN_USER`, and the final canonical
endpoint IPv4/port. `PLAYER_CIDR` defaults to public IPv4 (`0.0.0.0/0`), and
key-only SSH is not source-filtered by the guest firewall. Keep the logical
service name `echo` unless every DB, Web, Access, Supervisor, and test owner
coordinates the rename.

Read `../UNRESTRICTED_ROOT_WARNING.md` before deployment. Use a disposable,
single-player machine with no cloud role or valuable data.
