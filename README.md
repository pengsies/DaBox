# RelayForge unrestricted-root Flask challenge

> **Danger:** the intended final stage provides unrestricted UID-0 command
> execution on the Ubuntu host. Deploy only to a disposable, single-player VM
> with no IAM role, reusable credentials, sensitive data, or other workloads.
> Read `UNRESTRICTED_ROOT_WARNING.md` before installation.

This directory is a self-contained deployment root for the bounded-lifetime
RelayForge variant. Its public Web application is Flask served by Gunicorn
behind nginx HTTPS. PostgreSQL, Access, and Dispatcher run in Docker; the
privileged Supervisor, transient Workers, firewall, and sample endpoint run as
host services on Ubuntu.

The parent `relayforge-lab/` is a separate PHP/rotating variant. Do not replace
this directory's bounded 30–420 second Worker lifecycle with the parent's
seven-minute restart model.

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

## Directory map

| Path | Purpose |
|---|---|
| `web/` | Flask/Gunicorn application, teammate-derived UI, restricted DB calls, and intentional pickle gadget |
| `config/nginx.conf` | TLS edge, request limits, security headers, and proxy to `web:8080` |
| `db/init/` | Canonical schema, seed data, separate service roles, and restricted RPC state machine |
| `control/` | Access Controller and Dispatcher containers |
| `host/` | Supervisor, backend endpoint, firewall logic, cleanup, and systemd units |
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
| `EC2_RECOVERY_AND_UPGRADE.md` | Current-EC2 repair, upgrade rationale, verification, and recovery procedure |
| `DOCKER_COMPONENTS.md` | Exact five-container inventory and host/container boundary |

The original teammate Flask prototypes are retained outside deployment at
`../diff/teammate-web-source/`; `../diff/WEB.md` records what was retained and
what had to be adapted.

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
  the final diagnostic race produces genuine, unrestricted host root.
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
