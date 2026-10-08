# RelayForge blind-CTF discovery path

> **Organizer-only spoilers:** Do not give this document, `PLAYER_ATTACK_GUIDE.md`,
> `ATTACK_REPORT.md`, or the files under `attacks/` and `web/tools/` to players
> during a blind event. This document explains how a fair player could derive
> the intended solution and where RelayForge must provide an artifact or hint.

## Purpose

This is not another copy-and-paste exploit guide. It records the reasoning a
player should be able to follow:

1. what the player can observe;
2. what hypothesis that observation supports;
3. what experiment distinguishes that hypothesis from alternatives;
4. what evidence proves the boundary was crossed; and
5. what information cannot reasonably be guessed from a topology and login.

In a blind CTF, the organizer withholds the solution. The organizer must not
withhold every artifact needed to analyze the challenge. Supplying a binary or
sanitized source is normal; it does not stop the challenge from being blind.

> Blind means no exploit scripts or prewritten solution. It does not mean
> guessing undocumented constants, protocols, or memory layouts.

## Starting information

The initial handout may contain:

```text
Portal:   https://<TARGET>/login
Username: <PLAYER-USERNAME>
Password: <PLAYER-PASSWORD>
Goal:     obtain host UID 0 and read the generated root flag
Format:   RF{32-lowercase-hex-characters}
Scope:    the assigned disposable RelayForge host only
```

It may also include an accurate topology and the public surface:

```text
Player -- HTTPS 443 --> nginx --> Flask Web --> PostgreSQL
                                         ^          ^
                                         |          |
                                      Access     Dispatcher
                                                      |
                                                      | Unix socket
                                                      v
                                          host root Supervisor
                                                      |
                                                      v
Player -- TCP 25000-25099 ----------------> transient host Worker
                                                      |
                                                      v
                                      endpoint 127.0.0.1:19001
```

The diagram should show that nginx, Web, PostgreSQL, Access, and Dispatcher are
containers, while Supervisor, Worker, and the endpoint are Ubuntu-host
processes. The player does not connect directly to PostgreSQL, Access,
Dispatcher, Supervisor, or the private endpoint.

## Honest discoverability assessment

The topology and credentials alone are sufficient to test the normal portal
and tunnel. They are not sufficient to derive the complete intended exploit
chain fairly.

| Required discovery | From only the Web UI? | Fair source of knowledge |
|---|---:|---|
| `remember_prefs` is encoded Python pickle data | Partly | Browser tools, cookie policy, sanitized Web source |
| `JobTemplate` and `JobRunner` form an RCE gadget pair | No | Sanitized Web source or staged hint |
| Command output can be retrieved through a one-shot result route | No | Sanitized Web source or staged hint |
| The Web role has a narrow raw-request database RPC | No | Files readable after Web RCE |
| Access authorizes the first duplicate `profile` | No | Sanitized Access parser source |
| Worker executes the last duplicate `profile` | No | Worker binary analysis or source artifact |
| Worker protocol commands and callback layout | No | Production Worker binary |
| Supervisor diagnostic request and TOCTOU | After host shell | Host enumeration, Stage 2 marker, readable Supervisor source |

Therefore the recommended blind format is a **white-box/mixed-box CTF**:
players are not given an exploit or solution, but they receive sanitized source
and the exact Worker binary required for analysis. Alternatively, use the hint
ladder later in this document.

## Discovery principle: derive, do not randomly guess

Every intended transition should have this shape:

```text
observation -> hypothesis -> controlled test -> evidence -> next question
```

For example, a player should not be expected to randomly type `LEAK`. They
should find that string in the supplied Worker binary, determine that the
command is gated by a mode, and test it against safe and crafted Workers.

Marker text is a learning breadcrumb, not proof by itself. Its contents are
committed to the organizer repository. Proof also requires the expected UID,
process context, successful and denied reads, or behavior unique to that
privilege level.

## Phase 0: establish the normal product behavior

### Observation

The player logs in, submits a normal connection request, waits for it to run,
and receives a temporary link similar to:

```text
http://<TARGET>:25xxx/relay/<48-hex-token>/
```

That page returns the protected sample endpoint. Browser developer tools show
an authenticated Flask session and a second cookie named `remember_prefs`.

### Reasoning

The player now knows:

- HTTPS 443 is the control plane;
- the high TCP port is a transient data-plane Worker;
- the URL contains a bearer token;
- the endpoint is not directly public; and
- `remember_prefs` is additional client-controlled state worth inspecting.

The sample page's `RF{browser_tunnel_success}` text is explicitly a fake flag.
It proves tunnel functionality, not code execution.

### Evidence

- A wrong or expired token does not reach the endpoint.
- The issued link reaches the private page while the Worker is alive.
- Closing the tunnel ends that temporary listener.

## Phase 1: identify the remembered-preferences deserialization flaw

### Observation

The player inspects `remember_prefs`. Base64 decoding and Python pickle
disassembly identify a serialized object such as `prefs.RememberedPrefs`. The
portal's cookie-policy page names two reserved preference objects,
`JobTemplate` and `JobRunner`.

Useful analysis tools include browser developer tools, a base64 decoder, and
Python's `pickletools`. These inspect data; they do not supply the exploit.

### Hypothesis

The server may deserialize a client-controlled Python object after login. A
class allowlist is not necessarily safe when an allowed class has a dangerous
state-restoration hook.

### Fair artifact requirement

Provide sanitized copies of the Web authentication/remember-cookie code and
`prefs.py`, without vulnerability labels or exploit helpers. From that code,
the player can derive:

- the cookie is base64-decoded and unpickled;
- only three classes are permitted;
- `JobTemplate.__setstate__` stores attacker-controlled command text; and
- `JobRunner.__setstate__` launches the queued command.

Without that source or a strong hint, the exact state fields and ordering are
not reasonably inferable from the topology.

### Controlled test

The player builds a pickle containing the two allowed objects and chooses a
non-destructive proof command such as `id`. The sanitized Web source must also
make the bounded one-shot result mechanism discoverable; otherwise command
execution is blind because the spawned process's normal output is discarded.

### Evidence

The returned command output reports numeric UID/GID `65532:65532`. Through the
same primitive, the player locates and reads:

```text
/opt/relayforge/web/STAGE_1_WEB.txt
```

UID 65532 plus access to the Web-only marker demonstrates execution inside the
Flask container. The marker string alone does not.

### Next question

What capabilities are already available to the compromised Web process even
though it has no Docker socket, host mount, signing key, or Supervisor socket?

## Phase 2: enumerate the Web container and find the database pivot

### Observation

With command execution, normal enumeration reveals:

- `DB_HOST`, `DB_NAME`, and `DB_USER=relay_web` in the environment;
- read-only application code under `/opt/relayforge/web`;
- `app/db.py` and `app/raw_rpc.py`; and
- the Stage 1 marker's reference to a raw-request parser differential.

The player should inspect only the assigned lab. Standard questions are: who am
I, where am I, what files belong to this application, and which internal
services is this process already authorized to use?

### Hypothesis

The Web role may not control PostgreSQL generally, but it may have one
deliberately retained function that creates a request not expressible through
the public form.

### Controlled test

The player compares three operations:

1. query the current database identity;
2. attempt to read a private job table; and
3. call the raw-request RPC using the Web application's own database client.

### Evidence

- `current_user` is `relay_web`;
- private-table access fails with SQLSTATE `42501`; and
- the raw-request function returns a request UUID.

This proves a narrow capability, not a PostgreSQL takeover. There is no
database flag.

### Next question

Which valid raw option string will be approved by Access but produce different
runtime behavior in Worker?

## Phase 3: derive the cross-component parser differential

### Observation

The sanitized Access parser source retains all `profile` values but authorizes
the first. Analysis of the Worker artifact shows that it retains the last.

The candidate input is therefore:

```text
profile=safe&note=quarterly&profile=legacy
```

This is not an arbitrary guess. It is derived by comparing two parsers that
consume the same signed raw bytes.

### Controlled tests

Use both orders:

```text
profile=safe&note=quarterly&profile=legacy
profile=legacy&note=quarterly&profile=safe
```

The first should progress to a running Worker. The second should be rejected
because Access sees `legacy` first. A normal public-form request remains a safe
control Worker.

### Evidence for the Access half

Access permits only `safe`. Acceptance of the `safe -> legacy` order, combined
with rejection of the reversed order, demonstrates first-value authorization.

### Evidence for the Worker half

The same accepted request creates a Worker for which a legacy-only operation
succeeds. A safe control Worker returns `ERR command` for that operation. This
demonstrates last-value runtime selection.

Neither observation alone proves the whole differential. Together they show:

```text
same signed options -> Access selects first/safe -> Worker selects last/legacy
```

## Phase 4: analyze and authenticate to the native Worker

### Fair artifact requirement

Provide the exact production `relay-worker` AMD64 binary and its SHA-256. A
native memory-corruption challenge normally supplies its binary. Do not expect
players to infer command names, structure layout, or offsets from topology.

Nothing in the topology determines the words `TOKEN`, `LEAK`, `OVERFLOW`, the
128-byte callback offset, or the exact Supervisor diagnostic request. If no
artifact or hint exposes them, success is guessing rather than security
analysis.

Reasonable static-analysis tools include:

```text
file
strings
readelf
objdump
checksec
Ghidra or another disassembler/decompiler
```

The player should discover, rather than be handed, the relevant protocol
strings, the legacy-mode branch, the `worker_shell` function, and the debug
frame layout.

### Observation

The portal provides a high port and a 48-hex token to the request owner. Binary
analysis shows that a command connection must begin with `TOKEN <token>`, and
that a successful response includes the active job UUID.

### Controlled test

The player changes one token character and confirms `ERR auth`, then uses the
real token and receives the Worker banner plus `OK`.

### Evidence

The wrong-token/valid-token pair proves a real bearer-token boundary. Merely
finding an open port does not.

## Phase 5: combine the PIE leak with the callback overwrite

### Observation

Worker analysis shows:

- the executable is PIE;
- `LEAK` is enabled only in legacy mode;
- it returns the live address of `worker_shell`;
- the debug frame contains a 128-byte byte array followed by an eight-byte
  callback; and
- the copy accepts at most the 136-byte size of that complete frame.

### Hypothesis

The attacker cannot reliably hard-code a PIE address. The legacy disclosure
provides the current address, and a 136-byte payload can replace only the
adjacent callback:

```text
128 bytes of filler || little-endian worker_shell address
```

This is a bounded adjacent-field overwrite, not an unlimited stack copy. It
redirects an existing function pointer rather than injecting executable bytes.

### Controlled test and evidence

- A safe Worker answers `ERR command` to `LEAK`.
- The crafted Worker returns `worker_shell=0x...`.
- The leaked address changes across Worker processes when ASLR varies it.
- Supplying that exact address opens a shell.
- `id` reports the host `relay` account.
- Stage 2 is readable, while Stage 3 and the generated root flag return
  permission denied.

Those results prove an unprivileged host Worker shell. The browser's endpoint
page and `CONNECTED` response prove only tunneling, not shell access.

## Phase 6: enumerate the host Worker boundary

### Observation

From the `relay` shell, normal local enumeration reveals:

```text
/var/lib/relayforge/stages/STAGE_2_WORKER.txt
/run/relayforge/supervisor.sock
/opt/relayforge/runtime/supervisor.py
/proc/self/cgroup
```

The Stage 2 marker says that the next boundary is the exact `diagnostic.sh`
operation. The readable Supervisor implementation defines the request format
and validation logic. This information is discoverable only after the player
earns the host shell.

### Boundary checks the player should notice

Supervisor accepts `diagnose` only when:

- the kernel-reported peer UID is the host `relay` UID;
- the peer PID belongs to the supplied active Worker cgroup;
- the job has not expired;
- the basename is exactly `diagnostic.sh`; and
- the initial file is relay-owned, mode `0700`, single-link, regular, and has
  the exact approved content.

Trying from the Web container, another account, or an expired Worker should
fail. Those negative tests explain why the operation is not a generally
available root API.

## Phase 7: identify and prove the Supervisor TOCTOU

### Observation

Supervisor validates an opened descriptor, closes it, replies with a
`validated` acknowledgement, waits, and then executes the pathname again.

### Hypothesis

The checked object and executed object need not remain the same. After the
acknowledgement, the player can atomically replace the approved pathname during
the deterministic delay.

### Controlled comparison

- Without replacement, the benign file prints only the approved diagnostic
  message.
- With an acknowledged atomic replacement, the second pathname resolves to
  attacker-controlled content.

### Evidence

The replacement process reports effective UID 0 and, through the same command
stream, reads both:

```text
/var/lib/relayforge/stages/STAGE_3_ROOT.txt
/var/lib/relayforge/flag/root.txt
```

UID 0 proves the executing identity. The Stage 3 read confirms the root-only
host boundary. The randomized root flag proves the challenge objective. A
quoted marker string by itself proves nothing because marker contents are
source-known.

This is unrestricted Ubuntu-host root. Destroy and recreate the disposable VM
after a real player reaches this stage.

## Evidence chain summary

| Boundary | Strong evidence | What is not enough |
|---|---|---|
| Normal tunnel | Issued token reaches private endpoint | Fake page flag |
| Web RCE | Command output as UID 65532 plus Web marker access | Marker text alone |
| Database pivot | `relay_web`, private table denied, raw UUID returned | Knowing DB hostname |
| Access parser | Forward duplicate order accepted; reverse rejected | Request UUID alone |
| Worker parser | Legacy-only command works; safe control rejects it | Tunnel page loads |
| Worker memory corruption | Host `relay` shell and Stage 2 access | Leaked pointer alone |
| Host root | UID 0 plus root-only marker and randomized flag reads | Root-owned service exists |

## Recommended participant artifact

Create a separate `RelayForge-Player-Pack` rather than distributing the
organizer release. At minimum it should contain:

```text
README_PLAYER.md                 target placeholders, objective, scope, rules
topology.pdf or topology.png     accurate trust boundaries and public ports
web-source/                      sanitized auth, preferences, result mechanism
access-source/policy.py          sanitized first-profile parser
bin/relay-worker                 exact production AMD64 binary
bin/relay-worker.sha256          artifact integrity
```

Depending on desired difficulty, delay the Access parser source until after
Stage 1 or make it a scored hint. Supervisor source need not be in the initial
pack because the host shell can read the installed copy.

Remove vulnerability labels and comments from participant source, but do not
alter executable semantics. Record the participant artifact's hash so players
know they are analyzing the deployed version.

## Files that must not be in the blind player pack

Do not distribute the organizer release unchanged. Exclude at least:

```text
PLAYER_ATTACK_GUIDE.md
ATTACK_REPORT.md
BLIND_CTF_DISCOVERY.md
attacks/
web/tools/
tests/
MANIFEST.sha256 from the organizer bundle
CONTRACTS.md
deployment secrets, .env files, PEM files, private keys, and live flags
```

Also remove comments such as `INTENTIONAL-VULNERABILITY`, expected exploit
payloads, exact race timing notes, and tests that name the intended result.
The existing organizer package script deliberately excludes the compiled
`relay-worker`, so it cannot be reused as the player-pack builder: build the
exact deployed binary separately, record its hash, and package only the
sanitized participant files.

## Staged hint ladder

Hints should guide the next analysis question without supplying a command to
paste. One possible order is:

1. **Cookie surface:** Inspect every cookie created after login.
2. **Serialization:** Is `remember_prefs` just text, or a Python object?
3. **Gadget composition:** Two allowed preference classes interact during
   state restoration.
4. **Output:** The Web application has a bounded, one-shot result mechanism.
5. **Internal capability:** After Web execution, inspect application files and
   the process environment rather than scanning the Internet.
6. **Parser comparison:** Access and Worker do not agree about duplicate keys.
7. **Ordering:** Test both orders of the same two `profile` values.
8. **Native artifact:** The Worker binary contains a token-gated line protocol.
9. **PIE:** A runtime address disclosure must precede control redirection.
10. **Layout:** The interesting callback follows a 128-byte field.
11. **Host boundary:** Inspect the active Worker's cgroup and Supervisor socket.
12. **Race:** Compare the file object Supervisor validates with the pathname it
    later executes.

Hints may carry point penalties. Log which hint each playtester needed; if
nearly everyone requires the same hint, that information should probably be a
normal clue or artifact instead.

## Blind playtest checklist

Use testers who have not read the organizer repository or solution. Record:

- time spent before each hypothesis;
- commands and artifacts they naturally inspect;
- where they become stuck;
- hints requested;
- whether evidence is correctly interpreted; and
- whether they find an unintended shortcut.

A fair result is not that every beginner solves without hints. A fair result is
that each transition follows from available evidence, and that a hint resolves
an analysis gap rather than revealing an unknowable secret interface.

Before the event, confirm that participants receive no EC2 administrator PEM,
no Docker or sudo account, no organizer ZIP, and no live flag. The player
starting point is public HTTPS, the guest Web credential, the sanitized
artifact, and the declared Worker TCP range only.
