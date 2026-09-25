# RelayForge bounded-lifetime unrestricted-root attack review

Version: 2.0-unrestricted-root
Report date: 2026-09-25

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
  -> active-Worker-cgroup diagnostic RPC
  -> root Supervisor pathname TOCTOU
  -> unrestricted UID-0 shell on the Ubuntu host
  -> direct root-flag read
```

The final result is genuine, unrestricted host-root command execution and a
direct read of `/var/lib/relayforge/flag/root.txt`. This is not container root
and not a narrow flag-reading deputy. A solver can alter the VM, Docker,
firewall, accounts, and services, so the instance must be disposable and
single-player.

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
| RF-SUP-ROOT-01 | Supervisor | A root process validates one exact benign diagnostic, acknowledges it, delays, then executes the pathname again | Privileged validation/use race to real host root |

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

### 6. Race the root Supervisor diagnostic operation

Directly reading `/var/lib/relayforge/flag/root.txt` as `relay` must fail. The
diagnostic operation additionally accepts only UID `relay` from the exact
active Worker cgroup for the supplied job UUID.

The attacker creates `diagnostic.sh` in the active Worker's work directory as a
relay-owned, single-link, mode-`0700` regular file containing exactly:

```sh
#!/bin/sh
printf 'RelayForge diagnostic OK\n'
```

The shell sends the exact `diagnose` request. Supervisor opens the file with
`O_NOFOLLOW`, checks its metadata and bytes through that descriptor, closes it,
and returns `{"ok":true,"state":"validated"}`.

The intentional flaw is that validation and use do not share an open file
descriptor. During the deterministic 250 ms delay, the attacker atomically
replaces the checked pathname with an executable script that launches `/bin/sh`.
Supervisor then executes that pathname as UID 0 with the same Unix socket as
stdin, stdout, and stderr.

Primitive gained: an interactive, unrestricted host-root command stream for up
to the lesser of 60 seconds and the Worker's remaining lifetime. Reading the
flag is now an ordinary root operation, for example `id` followed by
`cat /var/lib/relayforge/flag/root.txt`.

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
- Diagnose additionally checks the caller's live Worker cgroup and an exact
  benign script before acknowledging the race window.
- Only the final pathname race crosses from the sandboxed `relay` Worker to
  unrestricted host root.

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

- the release manifest and static intentional-surface audit;
- Flask authentication, restricted-pickle, CSRF, and result-path tests;
- Web database-role and raw-RPC boundary checks;
- Access first-profile and Worker last-profile behavior;
- canonical signing, Dispatcher, Supervisor, diagnostic-gate, and root-exec
  TOCTOU tests;
- production Worker compilation, wrong-token rejection, browser forwarding,
  real `CONNECT` tunnelling, PIE leak, callback overwrite, and relay shell; and
- shell syntax and Compose-model validation.

Historical EC2 results for the bounded disclosure build do not prove this
unrestricted-root variant. A successful current `tests/run-vm.sh` execution
that proves `uid=0` and reads the exact root flag on a fresh disposable VM must
be recorded before claiming a complete deployed-VM PASS.

## Operational and adversarial notes

- The full-chain helper and this report disclose the intended solution. Keep
  maintainer material private if participants are expected to discover it.
- The root flag is generated per deployment and rotated by the reset script;
  no real flag value is committed to source.
- The acknowledgement and fixed delay make the intended pathname replacement
  deterministic enough for a teaching environment.
- Worker sandboxing and the pre-final-stage trust boundaries still prevent
  unintended shortcuts. The Supervisor itself is deliberately not sandboxed,
  because the selected learning outcome is genuine host root.
- Never deploy this stack alongside real data, credentials, other workloads,
  or any EC2 instance role. Destroy/reimage it after a solver reaches root;
  `reset-lab.sh` is not a security boundary against unrestricted UID 0.

For a participant-oriented walkthrough, including the exact container-to-host
trust-boundary transitions, see `PLAYER_ATTACK_GUIDE.md`.

## Authoritative implementation references

- `web/app/auth.py`, `web/prefs.py`, and `web/tools/exploit_stage1.py`
- `db/init/002-schema.sql.in`
- `control/policy.py`, `control/access.py`, and `control/dispatcher.py`
- `worker/relay-worker.c`
- `host/supervisor.py`
- `attacks/full_chain.py` and `attacks/exploit_supervisor_race.py`
- `CONTRACTS.md`, `SETUP.md`, and `tests/run-local.sh`
