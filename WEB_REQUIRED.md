# Flask Web integration contract

The integrated `web/` is a Flask application based on the teammate Web
prototype. nginx terminates TLS, Flask/Gunicorn serves the application, and the
canonical RelayForge database remains the sole source of user, target, request,
and job state.

## Container contract

The `web/` directory contains a `Dockerfile` that:

- builds for Linux AMD64;
- runs the application as numeric UID/GID `65532:65532`;
- listens on unencrypted HTTP port `8080` inside the Compose networks;
- starts Gunicorn without a development reloader; and
- includes Python's standard HTTP client for the Compose `/healthz` check.

The Web container is reached only as `web:8080` by nginx. It must not publish a
host port itself.

## Environment and storage contract

Compose supplies these variables:

```text
DB_HOST=postgres
DB_NAME=relayforge
DB_USER=relay_web
DB_PASSWORD=<generated deployment password>
FLASK_SECRET_KEY=<generated 256-bit application secret>
```

The application has a read-only root filesystem and a size-limited, private
`/tmp`. There is no persistent Web volume. One-shot exploit results use
`/tmp/relayforge-results`, must be regular same-UID files named as exactly 32
lowercase hexadecimal characters plus `.txt`, and are capped at 64 KiB.
Recreating the Web container clears them.

## HTTP contract

| Route | Required behavior |
|---|---|
| `GET /healthz` | Return exactly `ok\n` without querying PostgreSQL |
| `GET` or `POST /login` | Authenticate through `relay_web_api.authenticate` and create a cookie session |
| `POST /logout` | Destroy the session and redirect to login |
| `GET /` | Redirect to login or the authenticated dashboard |
| `GET /dashboard` | Require login, deserialize the `remember_prefs` cookie, and list the user's available targets |
| `POST /connections` | Validate CSRF, call only the safe-request RPC, and redirect to the owned HTML status page |
| `GET /connections/<uuid>` | Render the owned request state; refresh while provisioning and show the temporary browser URL only while running |
| `POST /connections/cancel` | Validate CSRF and request cancellation, then redirect back to the HTML status page |
| `POST /api/request` | Accept target, service, and integer duration; call only the safe-request RPC; return a request UUID as JSON; ignore any public `options` field |
| `GET /api/status/<uuid>` | Return the authenticated user's matching request/job status as JSON |
| `POST /api/cancel` | Validate CSRF and a UUIDv4 request ID, then request cancellation through the Web DB API |
| `GET /api/result/<name>` | Return a bounded result once and then remove it |

nginx expects port `8080`, terminates TLS on `443`, returns its own `/healthz`,
rate-limits login and mutation routes, proxies the Flask routes, and rejects
direct access to hidden files and the legacy `/var/cache/` path.

The HTML status page derives the Worker hostname from the browser's portal
host and renders `http://<host>:<port>/relay/<token>/`. The link is shown only
to the authenticated request owner while the job is running.

## Database contract

Normal Web code uses these functions:

```text
relay_web_api.authenticate(text, text)
relay_web_api.list_targets(text)
relay_web_api.submit_safe_request(text, text, text, integer)
relay_web_api.request_status(text, uuid)
relay_web_api.cancel_request(text, uuid)
```

`relay_web_api.submit_raw_request(text, text, text, integer, text)` remains
available to the intentionally compromised Web process but must not be exposed
by a normal public request route.

The intentional Stage 1 vulnerability is the teammate Flask prototype's
restricted-pickle gadget chain. Its exploit tooling and full-chain acceptance
tests therefore use the Flask cookie/API contract rather than the superseded
PHP `LegacyFormatter`, `ThemeWriter`, and `PendingExport` graph.

## Required verification

- Flask route, authentication, CSRF, and Stage 1 tests
- nginx-to-Gunicorn HTTPS integration
- safe-request and authenticated status tests against the real canonical DB
- Web-role privilege and raw-RPC boundary tests
- complete container security inspection and negative-path tests
- `tests/run-vm.sh` and the Flask-aware full-chain exploit

Container verification covers nginx, Flask, PostgreSQL, Access, and Dispatcher.
The real transient Worker and host Supervisor still require the documented
Ubuntu 24.04 AMD64 VM test.
