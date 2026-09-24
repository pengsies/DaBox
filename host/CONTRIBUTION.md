# Supervisor contribution and integration

## Status

The Supervisor teammate's prototype contributed four important design elements
to the integrated RelayForge path:

- kernel-verified Unix-socket peer credentials;
- Ed25519 verification of Access-created jobs;
- transient, unprivileged systemd Workers; and
- the intentionally vulnerable archive pathname reopen used by the final race.

Those ideas are retained in the deployable Supervisor mirrored in this folder.
The standalone C Supervisor, replacement Worker, rotation timers, and manual
commands from the prototype notes are not deployment inputs. They used wire
formats, state files, identities, and security boundaries that differ from the
agreed cross-team contract.

This shared version is authoritative for the bounded Flask variant. The parent
lab has intentionally diverged to rotating Worker generations.

## Integrated files

| Shared mirror | Purpose |
|---|---|
| `host/supervisor.py` | Signed-job broker, transient-Worker lifecycle, active-cgroup archive gate, and intentional bounded TOCTOU. |
| `host/relay-supervisor.service` | Root broker sandbox, runtime socket directory, narrow capabilities, and resource limits. |
| `tests/test_supervisor.py` | Component coverage for canonical jobs, signatures, exact Worker configuration, archive gates, and the race primitive. |
| `tests/test_systemd_units.sh` | Ubuntu systemd validation for the integrated units. |
| `tests/supervisor_systemd_integration.py` | Real signed Supervisor to transient Worker, tunnel, Worker exploit, cgroup gate, and archive-race test. |

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
- Archive accepts only the `relay` UID from the exact active Worker cgroup for
  that job. It returns at most 4096 bytes as `data_b64`. The documented
  validation-to-reopen race is the only intentional Supervisor flaw.

See `../CONTRACTS.md` for the complete shared contract.

## Verification sequence

Run from `responsibilities/shared`:

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
Access-to-root-flag path with the real firewall and network.

## Final deployment inputs

The VM run still requires `PUBLIC_IFACE`, `ADMIN_USER`, and the final canonical
endpoint IPv4/port. `PLAYER_CIDR` defaults to public IPv4 (`0.0.0.0/0`), and
key-only SSH is not source-filtered by the guest firewall. Keep the logical
service name `echo` unless every DB, Web, Access, Supervisor, and test owner
coordinates the rename.
