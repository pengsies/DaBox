# RelayForge unrestricted-root Flask challenge

> **Danger:** the intended final stage provides unrestricted UID-0 command
> execution on the Ubuntu host. Deploy only to a disposable, single-player VM
> with no IAM role, reusable credentials, sensitive data, or other workloads.
> Read `UNRESTRICTED_ROOT_WARNING.md` before installation.

This repository is the self-contained deployment root for the bounded-lifetime
RelayForge challenge. Its public Web application is Flask served by Gunicorn
behind nginx HTTPS. PostgreSQL, Access, and Dispatcher run in Docker; the
privileged Supervisor, transient Workers, firewall, and sample endpoint run as
host services on Ubuntu.

Each accepted Worker has one bounded 30–420 second lifetime. There is no
periodic seven-minute rotation or permanent Worker service in this deployment.

## Integrated path

```text
HTTPS -> nginx -> Flask -> restricted relay_web_api RPCs
                         -> PostgreSQL request queue
                         -> Access policy + Ed25519 signature
                         -> Dispatcher Unix RPC
                         -> host Supervisor
                         -> transient Worker -> configured IPv4 endpoint

Browser -> temporary tokenized Worker URL -> private HTTP endpoint
```

The authenticated Flask `remember_prefs` deserialization flaw is the intended
first foothold. It runs commands only as the unprivileged Web UID. The intended
chain then invokes the otherwise non-public raw-request RPC, reaches the
Access/Worker parser differential, exploits the legacy Worker callback, and
finishes by racing a validated diagnostic pathname into an unrestricted host
root shell.

## Access checkpoints

Three non-secret text breadcrumbs make the privilege transitions visible:

| Marker | Meaning | Can read it |
|---|---|---|
| `STAGE_1_WEB.txt` | Command execution in the Web container | Web UID 65532 |
| `STAGE_2_WORKER.txt` | Command execution in a native host Worker | Host `relayforge-ipc` group; normally the `relay` Worker |
| `STAGE_3_ROOT.txt` | Unrestricted host-root execution | Host UID 0 only |

Their exact runtime paths, modes, and limitations are in `STAGE_MARKERS.md`.
They are source-known learning breadcrumbs, not scoring secrets. The only real
flag remains the randomly generated, root-only
`/var/lib/relayforge/flag/root.txt`.

Stage 2 is group-readable because both native host identities that use the
Supervisor socket have `relayforge-ipc` as their primary group. The deployed
Dispatcher is a container without the host marker directory mounted, so its
matching numeric group does not make the file visible inside that container.
There is intentionally no database marker: reaching a PostgreSQL RPC or a
container UID 0 proves neither native-Worker access nor host root. Container
root remains constrained by that container's mounts, namespaces, dropped
capabilities, and no-new-privileges policy.

## Directory map

| Path | Purpose |
|---|---|
| `web/` | Flask/Gunicorn UI, restricted DB calls, and intentional pickle gadget |
| `config/nginx.conf` | TLS edge, request limits, security headers, and proxy to `web:8080` |
| `db/init/` | Canonical schema, seed data, separate service roles, and restricted RPC state machine |
| `control/` | Access Controller and Dispatcher containers |
| `host/` | Supervisor, backend endpoint, firewall logic, state cleanup, and systemd units |
| `worker/` | Native token-gated tunnel and intentional legacy callback flaw |
| `scripts/` | Installer, initialization, reset, firewall, SSH, and verification lifecycle |
| `tests/` | Source, component, container, endpoint, systemd, and VM acceptance tests |
| `attacks/` | Flask pickle payload and complete intended-chain verifier |
| `ATTACK_REPORT.md` | Flask-specific vulnerability chain, privilege boundaries, and current evidence status |
| `PLAYER_ATTACK_GUIDE.md` | Full-spoiler beginner walkthrough from the supplied IP and credentials to the root flag |
| `CONTRACTS.md` | Exact DB, signed-job, Unix-RPC, Worker, cancellation, and endpoint contracts |
| `WEB_REQUIRED.md` | Implemented Flask-specific Web contract |
| `SETUP.md` | Windows VM creation, Ubuntu Server installer choices, deployment, and acceptance |
| `UNRESTRICTED_ROOT_WARNING.md` | Mandatory deployment-risk and disposal guidance for this branch |
| `STAGE_MARKERS.md` | Exact three-stage access breadcrumbs, permissions, and interpretation |
| `EC2_RECOVERY_AND_UPGRADE.md` | Current-EC2 repair, upgrade rationale, verification, and recovery procedure |
| `DOCKER_COMPONENTS.md` | Exact five-container inventory and host/container boundary |

## Installed footprint and bounded reconciliation

The repository is an organizer/source tree; the installer does not copy it
wholesale onto the host. It reconciles three root-owned `/opt` trees to explicit
allowlists:

```text
/opt/relayforge/app/       compose.yaml plus only the nginx, control, DB-init,
                          and Web Docker build inputs
/opt/relayforge/runtime/   backend.py, cleanup_state.py, configure-firewall.sh,
                          firewall.py, harden-ssh.sh, init-challenge.sh,
                          reset-lab.sh, supervisor.py, verify-hardening.sh
/opt/relayforge/bin/       relay-worker
```

Repository documentation, tests, attack helpers, `web/tests/`, and
`web/tools/` remain in the verified source/release bundle but are absent from
the installed `/opt/relayforge` tree and from the Web image. On an upgrade,
entries outside these allowlists are removed only from those three managed
trees.

The installer also disables and removes exactly five obsolete prototype units:
`relay-cleanup.service`, `relay-cleanup.timer`, `relay-rotate.service`,
`relay-rotate.timer`, and the permanent `relay-worker.service`. It does not use
a wildcard, so transient `relay-worker-<UUID>.service` units are not selected.
It does not prune Docker globally, remove volumes, purge packages, delete user
home or `/tmp` files, or rotate existing secrets and the root flag. Existing
`/etc/relayforge`, PostgreSQL volume data, and `/var/lib/relayforge` state are
preserved unless the operator explicitly runs the destructive reset command.
The installer refuses to proceed while an unrelated running container is
present rather than interrupting it during Docker package reconciliation.

## Quick verification

From this directory:

```bash
python3 tests/check_integrated_stage.py
tests/run-local.sh
tests/run-container-integration.sh
tests/run-endpoint-integration.sh
tests/test_systemd_units.sh
python3 tests/supervisor_systemd_integration.py
```

The container suite uses a fake Supervisor only for the isolated
DB/Access/Dispatcher test. It does not claim that a real tunnel was created.
The endpoint suite launches the real Worker directly and proves both the raw
CONNECT tunnel and browser HTTP path to the sample private endpoint.

The real signed Supervisor-to-Worker and complete UID-0 chain require a clean
Ubuntu 24.04 AMD64 VM with systemd:

```bash
sudo ./scripts/install.sh \
  --acknowledge-unrestricted-root \
  --player-cidr 0.0.0.0/0 \
  --public-interface <interface> \
  --admin-user <user> \
  --endpoint-host 127.0.0.1 \
  --endpoint-port 19001
sudo ./scripts/init-challenge.sh
./tests/run-vm.sh https://127.0.0.1
```

Run that acceptance command on the VM itself with `127.0.0.1`; an EC2 instance
cannot reliably reach its own public IPv4 through the provider's edge. Use the
VM's public IPv4 or DNS name only for browser and client tests launched from a
participant computer. Permit inbound TCP 443 plus 25000–25099 from the intended
player CIDR. Keep TCP 5432, Flask 8080, and the host endpoint private.

`tests/supervisor_systemd_integration.py` can exercise the same host boundary
inside privileged Docker only when the Docker engine itself is native AMD64.
It reports a skip on ARM Docker Desktop because emulated AMD64 PID 1 cannot
reliably run systemd.

## Runtime decisions

- Web, Access, and Dispatcher have separate database roles and no direct
  private-table privileges.
- Access alone receives the job-signing private key; Supervisor receives only
  the public key.
- Dispatcher forwards the exact signed payload without reserializing it.
- Worker has no database credential and can reach only the configured canonical
  IPv4/port endpoint under the host firewall policy.
- The root Supervisor deliberately runs without its former systemd sandbox so
  the final diagnostic race produces genuine, unrestricted host root. Its
  unit explicitly resets `CapabilityBoundingSet=~` to the full kernel set and
  preserves `/run/relayforge` across restarts so the Dispatcher bind mount
  continues to refer to the live Supervisor socket directory.
- A relay lasts its requested 30–420 seconds. An authenticated owner can also
  request cancellation; Dispatcher retries until Supervisor confirms stop.
- `options_raw` controls only the safe/legacy parser exercise and never routing.
- One canonical endpoint IPv4/port is supported per deployment.

Host-specific values still required for deployment are `PUBLIC_IFACE`,
`ADMIN_USER`, and the final endpoint IPv4/port. `PLAYER_CIDR` defaults to
`0.0.0.0/0`, and the guest host firewall deliberately leaves key-only SSH
reachable from IPv4. The default is therefore a public, disposable CTF host;
AWS Security Group rules must also permit the intended traffic. Never place
real data or a privileged IAM role on this instance.

## Release archive

This repository release is the **organizer/open-book bundle**. It contains the
full-spoiler `PLAYER_ATTACK_GUIDE.md`, `ATTACK_REPORT.md`, and automated attack
helpers. For a blind event, prepare a separate participant handout that omits
those files; do not distribute this ZIP unchanged.

Create a deterministic, secret-filtered ZIP in an existing output directory,
then verify its contents and internal checksums:

```bash
./scripts/package-release.sh /path/to/output
python3 tests/verify-release-bundle.py \
  /path/to/output/RelayForge-Responsibilities-Flask-v1.zip
```

This organizer bundle contains a working host-root exploit. Do not distribute
it unchanged to participants and do not install it on a shared EC2 instance.

`MANIFEST.sha256` protects the checked-in integration tree. The release script
generates a fresh archive-local manifest after filtering generated files and
private-key material.
