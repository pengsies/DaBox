# Cross-Team Contracts

This document is the interface specification for the integrated Flask Web,
Access Controller, Dispatcher, Supervisor, and Worker. A teammate may
implement an internal component differently, but these observable contracts must remain
consistent.

## 0. HTTPS and Flask Web

nginx is the only public container listener and publishes HTTPS 443. Flask is
reachable only on the internal Compose network as `web:8080`.

Authenticated routes are `/dashboard`, `/cookie-policy`, `/connections[/<uuid>]`,
`/connections/cancel`, `/api/request`, `/api/status[/<uuid>]`, `/api/cancel`,
and `/api/result[/<name>]`. Mutations require the signed session and CSRF
token. Web calls only these DB functions:

```text
relay_web_api.authenticate(text, text)
relay_web_api.list_targets(text)
relay_web_api.submit_safe_request(text, text, text, integer)
relay_web_api.request_status(text, uuid)
relay_web_api.cancel_request(text, uuid)
```

`relay_web_api.submit_raw_request(...)` deliberately remains executable by the
Web role but has no HTTP route. It is reached only after the authenticated
`remember_prefs` pickle-gadget foothold.

## 1. Database to Access

Access connects as `relay_access`. It receives no direct private-table grants;
it may execute only its approved API functions.

### Claim request

```sql
SELECT * FROM relay_access_api.claim_request();
```

Result, in order:

```text
request_id uuid
user_id uuid
target_id text
service text
duration integer
options_raw text
```

### Resolve policy and destination

```sql
SELECT * FROM relay_access_api.policy_context(request_id);
```

Result, in order:

```text
grant_allowed boolean
max_duration integer
target_enabled boolean
endpoint_host text
endpoint_port integer
```

`endpoint_host` and `endpoint_port` come from the protected target row, never
from `options_raw`.

### Finish request

```text
finish_request(
  request_id,
  allowed,
  reason,
  job_id,
  payload_text,
  signature_bytes,
  launch_expires_at
)
```

For approval, `payload_text`, signature, job ID, and expiry are present. For
denial, no runnable job is created.

## 2. Access signed payload

Access serializes with ASCII, lexicographically sorted keys, and separators
`,` and `:` without spaces. It signs the exact serialized bytes with its
Ed25519 private key.

Exact keys:

```text
job_id
request_id
user_id
target_id
service
duration
endpoint_host
endpoint_port
options_raw
expires_at
```

Example logical content:

```json
{
  "job_id": "71ad6c2d-6271-46be-8859-087e91c4fcc6",
  "request_id": "7629c77b-ccab-482e-91eb-2ee7dc216bea",
  "user_id": "10000000-0000-4000-8000-000000000001",
  "target_id": "archive-echo",
  "service": "echo",
  "duration": 420,
  "endpoint_host": "10.20.0.15",
  "endpoint_port": 80,
  "options_raw": "profile=safe&note=quarterly&profile=legacy",
  "expires_at": "2026-09-14T10:01:00+00:00"
}
```

The real signed form is one canonical line, not pretty-printed JSON.

## 3. Database to Dispatcher

Dispatcher connects as `relay_dispatch` and uses only Dispatcher API functions.

```sql
SELECT relay_dispatch_api.expire_jobs();
SELECT * FROM relay_dispatch_api.claim_job();
```

`claim_job()` returns:

```text
job_id uuid
payload text
signature_hex text
```

Dispatcher treats `payload` as opaque signed bytes represented by an ASCII
string. It must not parse/reformat that string before forwarding it.

## 4. Dispatcher to Supervisor

Transport:

```text
AF_UNIX stream socket: /run/relayforge/supervisor.sock
framing: one ASCII/UTF-8 JSON object followed by newline
maximum request: 8192 bytes at Dispatcher
```

Request:

```json
{"op":"launch","payload":"<canonical JSON string>","signature_hex":"<128 lowercase hex>"}
```

Supervisor must verify the kernel-provided peer UID, exact framing/schema,
Ed25519 signature, canonical payload, UUIDs, expiry, duration, service,
endpoint, and options grammar before creating state.

Success response:

```json
{"ok":true,"port":25000,"token":"<48 lowercase hex>"}
```

Failure response:

```json
{"error":"<bounded generic reason>","ok":false}
```

`port` is the Worker listener exposed to the player. It is not the signed
destination `endpoint_port`.

Dispatcher records the reply using:

```text
relay_dispatch_api.finish_job(job_id, ok, port, token, reason)
```

Cancellation uses the durable DB states `stop-ready`, `stopping`, and
`stopped`. Dispatcher sends:

```json
{"op":"stop","job_id":"<canonical UUIDv4>"}
```

Supervisor returns `{"ok":true}` only after the transient unit is confirmed
inactive or already absent. A failed/ambiguous stop returns to `stop-ready` and
is retried; its port and state must not be released while the unit may be live.

## 5. Supervisor to Worker

Supervisor generates the random token and listening port after verifying the
signed job. It writes an exact ordered configuration:

```ini
token=<48 lowercase hex>
job=<canonical UUIDv4>
duration=<integer 30-420>
target_host=<signed canonical IPv4>
target_port=<signed integer 1-65535>
options=<signed strict options string>
```

Invocation:

```text
/opt/relayforge/bin/relay-worker <25000-25099> <worker.conf path>
```

Only the listening port and configuration path appear in process arguments.
The Worker writes `ready` in its working directory after binding successfully.

## 6. Player to Worker

Initial exchange:

```text
C: TOKEN <48 lowercase hex>
S: RelayForge worker job=<job UUID>
S: OK
```

Tunnel exchange:

```text
C: CONNECT
S: CONNECTED
```

After `CONNECTED`, that connection becomes a raw bidirectional TCP stream to
`target_host:target_port` until EOF or Worker termination. Debug exploitation
must use a separate authenticated connection.

For a browser, the authenticated owner receives this temporary capability URL:

```text
http://<RelayForge host>:<Worker port>/relay/<48 lowercase hex token>/
```

The browser sends HTTP first. This is deliberately not a general reverse
proxy: the Worker accepts only `GET` using HTTP/1.0 or HTTP/1.1. It validates
and strips the `/relay/` token prefix and reconstructs a minimal upstream
`GET`, `Host`, and `Connection: close` request for the signed private endpoint.
Missing or incorrect tokens receive an HTTP 403 response. This URL is a
short-lived bearer credential and expires when the Worker stops. The separate
authenticated `CONNECT` path remains a raw bidirectional TCP stream.

In safe mode, `LEAK` and `OVERFLOW` are rejected. In legacy mode, the deliberate
address leak and bounded callback overwrite are available.

## 7. Options grammar

```text
ASCII only
1-512 bytes
exactly 2 or 3 key/value pairs
exactly one note=[a-z0-9._-]{1,32}
one or two profile=safe|legacy pairs
no other keys
```

Normal value:

```text
profile=safe&note=portal
```

Intended differential value:

```text
profile=safe&note=quarterly&profile=legacy
```

Access uses the first profile; Worker uses the last. Supervisor validates the
shape but does not choose either interpretation.

## 8. Host and endpoint requirements

```text
PLAYER_CIDR     source allowed to reach HTTPS 443 and Workers 25000-25099;
                defaults to 0.0.0.0/0 for a public CTF
PUBLIC_IFACE    Ubuntu interface facing those networks
ENDPOINT_HOST   canonical IPv4 reached by Workers
ENDPOINT_PORT   endpoint TCP port; 19001 for the bundled fixture, otherwise a
                configured integer from 1 through 65535
```

The host firewall must allow UID `relay` to initiate TCP only to the configured
endpoint and reject its other egress. The endpoint owner must allow the
RelayForge host to reach `ENDPOINT_HOST:ENDPOINT_PORT`.

The host firewall accepts TCP 22 on `PUBLIC_IFACE` without a source-address
filter so a changed administrator address cannot strand the instance. SSH is
instead constrained to the configured administrator, public-key
authentication, and disabled forwarding. A cloud firewall may add a source
filter only when its CIDR is stable and a recovery mechanism exists.

The standard public-play deployment uses `PLAYER_CIDR=0.0.0.0/0`. A private
event may replace it with one canonical organisation or VPN CIDR. This setting
does not publish PostgreSQL, Flask's internal listener, or the private endpoint.

## 9. Current shared decisions

- One endpoint IPv4/port is supported per deployment.
- The command protocol provides a raw TCP tunnel; the same listener also
  provides tokenized HTTP forwarding for a normal browser.
- The logical service identifier remains `echo` for compatibility. Rename it
  to `http` only as one coordinated DB/Web/Access/Supervisor/test change.
- Access owns the private signing key; Supervisor receives only the public key.
- Worker has no DB credentials and runs as the unprivileged `relay` identity.
- Each Worker has one finite requested lifetime of 30–420 seconds. It does not
  use the parent lab's seven-minute `Restart=always` generation rotation.
- The authenticated request owner may cancel early through Flask; Dispatcher
  and Supervisor perform the actual confirmed unit stop.
