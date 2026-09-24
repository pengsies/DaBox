# Database integration handoff

This is the deployable database for the bounded Flask variant. The reviewed
prototype correctly identified two useful requirements retained here: separate
login roles for each service and deployment-supplied passwords rather than
credentials embedded in SQL.

The integrated version adds the schema, state machine, endpoint data, restricted
RPCs, privilege revocation, and input bounds required by the rest of RelayForge.
Historical export files are reference material only and are not deployment
inputs.

## Canonical files

| File | Purpose |
|---|---|
| `init/001-init.sh` | Validates the deployment variables and passes DB passwords plus the trusted endpoint to `psql`. |
| `init/002-schema.sql.in` | Creates the roles, private tables, seed data, state transitions, least-privilege API functions, and privilege self-audit. |
| `../compose.yaml` | Selects the digest-pinned PostgreSQL image and wires the DB, Access, and Dispatcher credentials and networks. |
| `../.env.example` | Non-secret disposable-test values and the default loopback endpoint fixture. |

There is deliberately no separate database Dockerfile. PostgreSQL is configured
from the pinned upstream image in `compose.yaml`, with these initialization files
mounted read-only.

## Runtime boundary

```text
Flask Web -- relay_web_api.* --> private requests/cancellation
Access -- relay_access_api.* --> signed ready jobs
Dispatcher -- relay_dispatch_api.* --> launch/stop state
Dispatcher -- Unix RPC --> host Supervisor --> bounded transient Worker
```

The application roles have no direct privileges on the private tables. The
Worker has no database account, credential, or network dependency; it receives
only a root-created configuration from the Supervisor.

## Verification

Run from `responsibilities/shared`:

```bash
python3 tests/check_integrated_stage.py
python3 tests/static_audit.py
tests/run-container-integration.sh
tests/run-endpoint-integration.sh
```

The disposable container suite proves the real DB/Access boundary and the real
DB/Access/Dispatcher boundary. Its Dispatcher phase uses the explicitly named
`fake-supervisor` fixture, so it does not claim to create a real tunnel.

The real Supervisor/Worker boundary is covered separately by:

```bash
python3 tests/supervisor_systemd_integration.py
```

The complete deployed chain, including firewall and host identities, must be
verified on the Ubuntu VM with `tests/run-vm.sh`.
