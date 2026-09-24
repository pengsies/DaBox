# RelayForge container inventory

The deployable stack contains exactly five Docker Compose services. The
release ZIP contains every Compose file, Dockerfile, application build context,
database initializer, and pinned external-image reference needed to create
them on Ubuntu AMD64.

| Service | Image source | Purpose | Public exposure |
|---|---|---|---|
| `edge` | Pinned `nginx:1.30.4-alpine3.24` image | TLS termination, limits, headers, and reverse proxy to Flask | Host TCP 443 |
| `web` | Built from `web/Dockerfile` on pinned `python:3.12.14-slim-bookworm` | Flask/Gunicorn login, dashboard, safe API, and intended authenticated pickle foothold | Internal TCP 8080 only |
| `postgres` | Pinned `postgres:16.15-alpine3.23` image | Canonical users, targets, requests, jobs, state machine, and restricted RPC schemas | Internal TCP 5432 only |
| `access` | Built from `control/Dockerfile` on pinned Python base | Policy evaluation and Ed25519 job signing | No published port |
| `dispatcher` | Same `control/Dockerfile`; different command and identity | Claims signed jobs and sends launch/stop RPCs to the host Supervisor | No published port |

The SHA-256 image digests are authoritative in `compose.yaml` and the two
Dockerfiles. Tags in this table are human-readable labels only.

## Included Docker inputs

```text
compose.yaml
.env.example
config/nginx.conf
web/Dockerfile
web/.dockerignore
web/requirements.txt
web/app/
web/templates/
web/static/
control/Dockerfile
control/requirements.txt
control/*.py
db/init/
tests/compose.*.yaml
tests/systemd/Dockerfile
```

`.env.example` contains non-secret disposable test placeholders. The installer
creates `/etc/relayforge/compose.env` with fresh deployment secrets and never
copies a development `.env` into the release.

## Networks and data

| Compose object | Role |
|---|---|
| `edge_net` | Bridge used by the TLS edge |
| `frontend_net` | Internal edge-to-Web network |
| `db_net` | Internal Web/Access/Dispatcher-to-PostgreSQL network |
| `postgres_data` | Persistent PostgreSQL volume |

Only nginx publishes a Docker port. PostgreSQL and Flask are not bound to host
ports. Dispatcher receives the host Supervisor socket as a read-only bind; the
Access container receives only the signing private key it needs; nginx receives
only the TLS directory.

## Components deliberately not containerized

These run directly under Ubuntu systemd because their security boundary or
network role depends on the host kernel:

| Host component | Unit/process |
|---|---|
| Signed-job Supervisor | `relay-supervisor.service` |
| Bundled HTTP endpoint | `relay-backend.service` on `127.0.0.1:19001` |
| Firewall application | `relayforge-firewall.service` |
| Compose lifecycle | `relayforge-stack.service` |
| Per-job native tunnel | transient `relay-worker-<uuid>.service` |

The Worker is intentionally **not** a Docker service. A real accepted request
causes the Supervisor to create a transient systemd Worker listening on one
host port from `25000-25099`.

## Test-only containers

The acceptance suites may also create a disposable `sample-endpoint`, a
`fake-supervisor`, and a privileged nested Ubuntu-systemd integration
container. They exist only to isolate test phases, are removed by the test
runners, and are not part of the five-service deployed Compose stack.

## Online and offline meaning

The standard ZIP does not embed Docker layer archives. On first installation:

```text
nginx + PostgreSQL images    pulled by digest
Python base image            pulled by digest
Web image                    built locally
Access/Dispatcher image      built locally once and reused
native Worker                compiled locally for AMD64
```

This keeps the reviewed release small and prevents host-architecture mistakes.
The VM needs outbound Internet access for Ubuntu packages and the pinned image
layers. An offline image bundle, if ever required, should be generated and
verified separately on a trusted AMD64 machine; it is not interchangeable with
this source release.
