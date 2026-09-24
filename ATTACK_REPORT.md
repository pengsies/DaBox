# RelayForge bounded Flask attack and adversarial review

Version: 1.1
Report date: 2026-09-24

## Scope

This report covers the deployable bounded Flask implementation in this
directory. It does not describe the separate parent PHP implementation or its
seven-minute Worker-generation rotation. In this build, each Worker has one
finite requested lifetime of 30–420 seconds and may be cancelled early by the
authenticated request owner.

The challenge intentionally contains a chained set of vulnerabilities. It must
run only on an isolated, disposable training host with no real data or
privileged cloud role.

## Intended route

```text
known guest login
  -> authenticated Flask remember_prefs pickle RCE
  -> relay_web database credential and restricted raw-request RPC
  -> Access-first / Worker-last profile parser differential
  -> Ed25519-signed transient Worker
  -> token-gated Worker PIE leak and bounded callback overwrite
  -> host shell as the unprivileged relay user
  -> active-Worker-cgroup archive RPC
  -> root Supervisor pathname TOCTOU
  -> disclosure of the root-only flag
```

The final result is disclosure of `/var/lib/relayforge/flag/root.txt`. The
intended solution does not grant UID 0, unrestricted `sudo`, or a persistent
root shell.

## Starting position

The player is given HTTPS access to the Flask portal and TCP access to the
configured Worker range, normally `25000–25099`. The intentionally public
training account is `guest / guest-relay-2026`.

The player is not assumed to have SSH, a host account, a database credential,
the signing key, the Supervisor socket, a Worker token, Docker access, or host
filesystem access. The internal HTTP endpoint is not published directly.

## Intentional vulnerability inventory

| ID | Component | Deliberate behavior | Teaching purpose |
|---|---|---|---|
| RF-WEB-01 | Flask trusted pickle classes | `JobTemplate` queues attacker-controlled shell text and `JobRunner` executes it | Restricted deserializers can retain dangerous allowed gadgets |
| RF-WEB-02 | Flask authentication | Authenticated `remember_prefs` accepts client-controlled restricted-pickle data | Authenticated Python deserialization foothold |
| RF-DB-01 | PostgreSQL | Compromised `relay_web` may call the otherwise non-public raw-request RPC | Turn Web RCE into a narrow internal capability |
| RF-PARSE-01 | Access | Policy uses the first `profile` value | Authorization parser semantics |
| RF-PARSE-02 | Worker | Runtime behavior uses the last `profile` value | Cross-component parser differential |
| RF-WORKER-01 | Worker | A bounded 136-byte copy may overwrite a callback after a 128-byte buffer | Controlled memory corruption without an unbounded copy |
| RF-WORKER-02 | Worker | Legacy mode discloses the live `worker_shell` address | Demonstrate a PIE information leak |
| RF-SUP-01 | Supervisor | A root process validates a pathname, delays, and then reopens it | Privileged validation/use race |

These are dependencies in one intended chain, not independent public routes to
the flag.

## Exploitation sequence

### 0. Authenticate

The player logs in at `/login` using the guest account. Flask establishes a
signed session and a `remember_prefs` cookie. The dashboard, connection state,
cancellation, and one-shot result routes all require an authenticated session.

Normal portal submissions call only `submit_safe_request`; a public form cannot
submit arbitrary raw Worker options.

Primitive gained: ordinary authenticated Web access only.

### 1. Exploit the remembered-preferences pickle

The attacker replaces the authenticated `remember_prefs` cookie with a base64
Python pickle containing the allowed classes:

```text
JobTemplate -> JobRunner
```

When `/dashboard` processes the cookie, `JobTemplate.__setstate__()` queues the
chosen command and `JobRunner.__setstate__()` launches it with
`subprocess.Popen`. The process runs inside the Web container as numeric
UID/GID `65532:65532`, not as root.

Because the command is detached, the verifier redirects output to a bounded
same-UID regular file under:

```text
/tmp/relayforge-results/<32-lowercase-hex>.txt
```

The authenticated `GET /api/result/<name>` route returns that file once and
then removes it. The directory is an ephemeral size-limited tmpfs and is not
served directly by nginx.

Primitive gained: command execution as the unprivileged Web UID.

### 2. Exercise the restricted Web database capability

The Web process environment necessarily contains `DB_HOST`, `DB_NAME`,
`DB_USER=relay_web`, and its generated deployment password. From the foothold,
the attacker can use `psycopg2` or the retained `python3 -m app.raw_rpc` helper.

The role boundary must still hold:

```sql
SELECT current_user;                  -- relay_web
SELECT 1 FROM private.jobs LIMIT 1;   -- SQLSTATE 42501
```

The role cannot read private tables, claim Access/Dispatcher work, sign jobs,
or launch Workers. It deliberately retains only the bounded raw-request
capability needed for the challenge.

Primitive gained: permission to enqueue one bounded raw request as the current
Web principal.

### 3. Cross the profile parser differential

The intended request targets `archive-echo`, uses logical service `echo`, and
supplies a duplicate-profile option string such as:

```text
profile=safe&note=quarterly&profile=legacy
```

Access validates the shared grammar and authorizes using the first profile,
which is `safe`. It resolves the protected endpoint IPv4/port, preserves the
exact raw option bytes, and signs a canonical job envelope with its private
Ed25519 key.

The Worker parses the same valid string but retains the final profile, which is
`legacy`. Options cannot supply an endpoint, path, URL, or command; routing
continues to come only from the protected and signed target record.

Primitive gained: a legitimate signed request for a legacy-mode Worker.

### 4. Cross the privileged launch boundary

Dispatcher claims only ready jobs and sends the exact Access-signed envelope
over `/run/relayforge/supervisor.sock`. The root Supervisor verifies:

- the kernel peer identity is `relay-dispatch`;
- the exact bounded request schema and canonical UUIDs;
- the Ed25519 signature and expiration;
- duration, target, service, endpoint, and options constraints; and
- an available port in the configured Worker range.

Supervisor creates root-owned state and starts a transient systemd unit running
`/opt/relayforge/bin/relay-worker` as the nonlogin `relay` identity. It returns
a random 48-hex token and allocated port only after readiness succeeds.

Each Worker runs for the requested 30–420 seconds. It does not automatically
rotate into seven-minute replacement generations.

Primitive gained: temporary connection material for one signed Worker.

### 5. Reach and exploit the Worker

The same listener provides two interfaces:

- a normal browser can request `http://<host>:<port>/relay/<token>/` and receive
  the private endpoint's HTTP response; and
- the challenge protocol begins with `TOKEN <token>`, rejects a wrong token
  with `ERR auth`, and accepts `CONNECT`, `LEAK`, and `OVERFLOW` as permitted by
  the selected profile.

An authenticated `CONNECT` must return `CONNECTED` and then relay real bytes to
the signed private endpoint. This proves the tunnel is not a fabricated
reachability banner.

In legacy mode, `LEAK` returns the live `worker_shell` address. The controlled
overflow body is exactly:

```text
128 bytes of filler || little-endian worker_shell address
```

The 136-byte structure allows the callback overwrite while retaining PIE, NX,
stack-protector, full RELRO, and immediate binding in the production build.
Calling the overwritten callback opens a command shell as `relay` inside the
active transient Worker unit and its systemd sandbox.

Primitive gained: command execution as the unprivileged host `relay` user.

### 6. Race the root Supervisor archive operation

Directly reading `/var/lib/relayforge/flag/root.txt` as `relay` must fail. The
archive operation additionally accepts only UID `relay` from the exact active
Worker cgroup for the supplied job UUID.

The attacker creates an owned regular `race.log` in the active Worker's work
directory and requests that it be archived. Supervisor first calls `lstat()`
and checks that the object is a relay-owned, single-link regular file no larger
than 4096 bytes.

The intentional flaw is that validation and use do not share an open file
descriptor. During the deterministic 100 ms delay, the attacker atomically
replaces the checked pathname with a symlink to the root flag. Supervisor then
calls `os.open(path, ...)` without `O_NOFOLLOW`, follows the replacement link as
root, and returns up to 4096 bytes as base64.

Primitive gained: disclosure of the root-only flag through a privileged
confused deputy. The attacker still does not obtain a root shell.

## Why the ordering is enforced

- Public Flask routes discard raw options and submit only a fixed safe profile.
- The raw-request RPC is available only after compromising the Web process and
  obtaining its restricted database capability.
- Access alone holds the signing private key.
- Dispatcher and Supervisor accept only valid, current Access envelopes.
- The endpoint comes from protected target data and is included in the signed
  payload; options cannot redirect the tunnel.
- Debug commands require both the parser differential and the random Worker
  token.
- Worker command execution is `relay`, not root, and the unit is sandboxed.
- Archive additionally checks the caller's live Worker cgroup.
- Only the final pathname race lets root-only data cross the privilege boundary.

## Browser usability versus attack protocol

The portal's temporary link is a usability path for accessing the approved
private HTTP endpoint. It is not itself the privilege-escalation exploit. The
full intended attack uses a separate authenticated raw Worker connection for
the legacy debug commands because `CONNECT` commits its connection to tunnel
mode until EOF.

An `ERR_INVALID_HTTP_RESPONSE` in a browser normally means an obsolete
raw-protocol-only Worker was installed. The deployed binary for this variant
must contain the `HTTP/1.1` and `/relay/` markers and must be built from the
current release source rather than a stale extracted directory.

## Verification status

Current source-level and local component evidence includes:

- the 96-file manifest and static intentional-surface audit;
- Flask authentication, restricted-pickle, CSRF, and result-path tests;
- Web database-role and raw-RPC boundary checks;
- Access first-profile and Worker last-profile behavior;
- canonical signing, Dispatcher, Supervisor, archive-gate, and TOCTOU tests;
- production Worker compilation, wrong-token rejection, browser forwarding,
  real `CONNECT` tunnelling, PIE leak, callback overwrite, and relay shell; and
- shell syntax and Compose-model validation.

The EC2 deployment has separately shown a healthy five-container stack and a
46/46 host-hardening verification result. That does not by itself prove the
complete attack chain. A successful current `tests/run-vm.sh` execution ending
in an exact root flag must be recorded before claiming a complete deployed-VM
PASS. Earlier partial EC2 attempts and failures must not be presented as full
chain success.

## Operational and adversarial notes

- The full-chain helper and this report disclose the intended solution. Keep
  maintainer material private if participants are expected to discover it.
- The root flag is generated per deployment and rotated by the reset script;
  no real flag value is committed to source.
- The race is probabilistic by design, although the fixed delay and retrying
  helper make it suitable for a teaching environment.
- Session limits, finite Worker lifetimes, cancellation, firewall restrictions,
  container isolation, and systemd sandboxing reduce unintended shortcuts and
  persistence but are not substitutes for running the lab on a disposable host.
- Never deploy this intentionally vulnerable stack alongside real data,
  credentials, or a privileged EC2 instance role.

## Authoritative implementation references

- `web/app/auth.py`, `web/prefs.py`, and `web/tools/exploit_stage1.py`
- `db/init/002-schema.sql.in`
- `control/policy.py`, `control/access.py`, and `control/dispatcher.py`
- `worker/relay-worker.c`
- `host/supervisor.py`
- `attacks/full_chain.py` and `attacks/exploit_supervisor_race.py`
- `CONTRACTS.md`, `SETUP.md`, and `tests/run-local.sh`
