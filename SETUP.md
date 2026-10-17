# RelayForge Windows-to-Ubuntu setup and acceptance guide

> **Unrestricted-root variant:** a successful player obtains real UID 0 on the
> Ubuntu host. Use a disposable, single-player VM with no IAM role, reusable
> credentials, sensitive data, or other workloads. Do not install this branch
> on a shared or persistent server. The assigned Group 30 EC2 is suitable only
> while it is dedicated to this lab, has no valuable data or IAM role, and is
> recreated after a player reaches root. Read `UNRESTRICTED_ROOT_WARNING.md`
> first.

This is the authoritative setup guide for the bounded-lifetime Flask release.
The RelayForge host must be a native **Ubuntu Server 24.04.x LTS AMD64**
installation. Ubuntu Desktop, WSL2, and Docker Desktop are not acceptance
hosts: the complete design relies on the Ubuntu host's systemd, cgroups,
Unix-socket peer credentials, iptables, and transient Worker services.

The release ZIP is an online deployment bundle. It includes Compose,
Dockerfiles, pinned image references, application build contexts, database
initializers, host services, tests, and installer scripts. It intentionally
does not contain preloaded multi-gigabyte Docker image layers or generated
secrets. The Ubuntu VM therefore needs Internet access while the installer
downloads packages and pulls/builds images.

For recovery of the existing Group 30 EC2, including why each permission and
service change is made, see `EC2_RECOVERY_AND_UPGRADE.md`.

## How the Vulnerability Chain Was Designed and Built

This section records the implementation process behind the challenge. It
starts with the ordinary relay service and explains how each deliberate
weakness was added at a specific trust boundary, what capability that stage
provides, and what protections remain around it. The design goal was a
connected learning path, not five unrelated ways to run commands:

```text
authenticated portal
  -> command execution in the Web container
  -> narrow request-enqueue capability
  -> Access/Worker interpretation mismatch
  -> temporary native Worker as host relay
  -> root Supervisor pathname race
  -> unrestricted host UID 0
```

The implementation deliberately preserves intermediate boundaries. Web
execution remains container UID 65532; the database pivot cannot sign jobs;
the Worker is a host process running as unprivileged `relay`; and only the
last Supervisor stage reaches host UID 0. The sections below describe how the
authors assembled that path and why the surrounding controls were retained.

### Build Phase 1: Establish the Relay Service Before Adding the Challenge

The starting point was a real service to investigate: an authenticated Flask
portal accepts a connection request, PostgreSQL stores it, Access makes a
policy decision and signs approved job data, Dispatcher forwards that signed
data to the host, and a temporary Worker tunnels to a private HTTP fixture.
The Docker and host split was chosen before adding the vulnerabilities because
the learning objective depends on crossing distinct privilege domains.

The production stack has five containers: Nginx edge, Flask Web, PostgreSQL,
Access, and Dispatcher. The backend endpoint, Supervisor, firewall controls,
and transient Worker are host services. The endpoint is pinned to a configured
host IPv4 and port; request options do not control routing. Public ingress is
HTTPS on 443, while a Worker receives a temporary port from 25000-25099 only
after an approved request is dispatched. This gives the first investigation a
normal browser workflow before any shell or binary-analysis tools are needed.

The common container policy in [compose.yaml](compose.yaml) was then used to
make the Web foothold meaningful but contained: services are read-only where
possible, drop Linux capabilities, enable `no-new-privileges`, have resource
limits, and do not receive the Docker socket. Web runs as UID 65532. Its
database network access is intentional; host-control access is not.

### Build Phase 2: Add the Authenticated Web Foothold

The first challenge flaw was placed in the remembered-preferences feature.
Login issues a `remember_prefs` cookie representing `RememberedPrefs`, and the
authenticated dashboard restores that cookie when it renders. The cookie is
base64 encoded and the unpickler has a class allowlist, because the lesson is
that a restricted deserializer can still be unsafe when an allowed object's
state hook has side effects.

The implementation adds two allowed classes with complementary hooks:
`JobTemplate.__setstate__` stores a command in a process-local queue, and
`JobRunner.__setstate__` consumes that queued command and starts it with
`subprocess.Popen(..., shell=True)`. Pickle's object restoration order joins
the hooks into one gadget. The authenticated trigger is the call to
`remembered_username()` on the dashboard route. Relevant implementation is in
[web/prefs.py](web/prefs.py), [web/app/auth.py](web/app/auth.py), and
[web/app/__init__.py](web/app/__init__.py).

The child is detached and its ordinary stdout/stderr are discarded. To make
the first-stage result testable, the exploit payload writes output to a
temporary result file, and Web exposes an authenticated, size-bounded,
one-shot read route. That mechanism is an observation channel for the lab,
not an additional privilege escalation. It was important to keep the process
in the Web container so the result proves only UID 65532 execution, not host
access.

Excerpt showing how the allowed state hooks compose, from
[web/prefs.py](web/prefs.py):

```python
class JobTemplate:
    pending: list[str] = []

    def __setstate__(self, state) -> None:
        self.__dict__.update(state)
        JobTemplate.pending.append(self.command)


class JobRunner:
    def __setstate__(self, state) -> None:
        self.__dict__.update(state)
        if JobTemplate.pending:
            subprocess.Popen(
                JobTemplate.pending.pop(), shell=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
```

The class allowlist and authenticated restore point are separate parts of the
setup. A class hook alone is inert if no attacker-controlled pickle reaches
it; a client-controlled pickle is also not sufficient if every permitted class
is harmless. The challenge intentionally combines both conditions.

One deployment limitation remains part of the design record: the public login
form does not reveal the seeded account. An IP-only event therefore needs an
organizer-supplied account clue or a separately tested, bounded recovery step.
The login throttle makes arbitrary online wordlist guessing a poor substitute
for a designed entry clue.

### Build Phase 3: Turn Web Execution into a Narrow Database Pivot

After the Web foothold was established, the next design decision was to avoid
giving the compromised process broad database authority. PostgreSQL separates
private tables from service APIs. `relay_web` cannot read private request/job
tables or call Access and Dispatcher APIs, but it is granted execution on one
additional `SECURITY DEFINER` function,
`relay_web_api.submit_raw_request(...)`. The ordinary Web routes continue to
call only `submit_safe_request`; no public HTTP handler accepts raw options.

The adapter for the retained function is present in
[web/app/db.py](web/app/db.py), and its SQL definition and explicit grants are
in [db/init/002-schema.sql.in](db/init/002-schema.sql.in). The function uses
the same bounded enqueue path as ordinary requests and returns a request UUID.
This was designed as a post-compromise capability: it lets an attacker with
Web command execution ask the normal Access service to evaluate a request, but
does not provide the signing key, private job rows, or direct Worker launch.

The vulnerable grant is therefore a narrow exception surrounded by explicit
revocations. The normal dashboard remains a useful control case because it
cannot submit arbitrary `options_raw`; the raw function is only reachable
through the already-compromised Web process.

### Build Phase 4: Create the Access/Worker Parser Mismatch

The cross-service flaw was added by having Access and Worker independently
interpret the same bounded option string. The grammar permits one or two
`profile` pairs and exactly one `note`. Access chooses the first profile and
requires it to be `safe`; the Worker processes pairs in order and keeps the
last profile. With `safe` first and `legacy` last, Access approves while the
Worker enables its legacy debug commands. Reversing the order is the negative
case: Access rejects it.

This mismatch gives the challenge a controlled policy lesson without placing a
target host, URL, path, or command in the raw options. The endpoint remains
resolved from a protected target record. Access still checks user grant,
target enablement, service, duration, and grammar, then signs the canonical
job envelope. Dispatcher forwards those exact signed bytes and Supervisor
validates them before launch. The flaw is the disagreement about duplicate
keys, not a bypass of signature verification or routing integrity.

The implementation is split deliberately: Access semantics are in
[control/policy.py](control/policy.py), and Worker semantics are in
[worker/relay-worker.c](worker/relay-worker.c). Keeping the parsers separate
makes the differential real: neither component calls the other's parser or
shares a parsed result.

### Build Phase 5: Build the Native Worker Stage

The Worker was implemented as a native AMD64 host binary so the exercise could
move from container command execution to an unprivileged host identity. It
starts only after Access signs an approved request and Dispatcher delivers it
to Supervisor. Supervisor creates a transient systemd unit under `relay`,
chooses an available port in 25000-25099, generates a 48-hex bearer token, and
starts the Worker for a bounded 30-420 seconds. The port and token are returned
to the authenticated request owner only after readiness succeeds.

The Worker retains a normal tunnel command (`CONNECT`) and a browser HTTP
relay. The intentional debug behavior is only enabled when the parser has
selected legacy mode. `LEAK` prints the current address of `worker_shell` to
illustrate why PIE alone does not prevent exploitation when an address is
disclosed. `OVERFLOW` accepts no more than the full 136-byte frame. Its first
128 bytes are data and its next eight bytes are the callback pointer. The
bounded copy then invokes the callback. Redirecting it to the leaked shell
function gives a shell as `relay`, not root.

The struct size and offset are compile-time asserted in
[worker/relay-worker.c](worker/relay-worker.c). The compiler flags in
[worker/Makefile](worker/Makefile) retain PIE, stack protection, NX, RELRO, and
immediate binding. Those defenses are not disabled to make the exploit work;
the intended exercise uses information disclosure plus callback replacement,
not injected shellcode or an unbounded overwrite.

The artifact used for analysis must be the one the host executes. The installer
builds `/opt/relayforge/bin/relay-worker`, and Compose mounts that exact file
read-only into Nginx. `robots.txt` advertises the artifact path so a player can
find it through ordinary web enumeration instead of guessing a hidden URL.
The Nginx locations are in [config/nginx.conf](config/nginx.conf), and the
mount and byte-identity verification are defined in
[compose.yaml](compose.yaml) and `scripts/verify-hardening.sh`.

### Build Phase 6: Add the Root Supervisor Race

The final stage was added to the host Supervisor, not to Docker or the Web
container. The `diagnose` operation first restricts its caller to the `relay`
UID in the exact active Worker cgroup, checks the job deadline and exact
filename, and validates a benign `diagnostic.sh` through an open descriptor.
The file must be a regular file, relay-owned, single-link, mode 0700, the
expected size, and contain the exact approved bytes. These checks make the
operation specific to the current Worker and rule out filename, symlink, and
content substitutions before validation.

The deliberate race is introduced after those checks: Supervisor closes the
validated descriptor, sends the `validated` acknowledgement, waits 250 ms,
then opens the pathname again implicitly by executing it with `Popen(path)`.
The Worker can atomically replace that pathname during the interval. Because
validation and execution refer to the same name but not the same open file
object, the root process may execute different bytes from the ones it checked.
The Supervisor passes the same socket to the child as standard input, output,
and error so successful replacement is observable as a command stream.

The service unit is deliberately not sandboxed from the host privilege domain:
it runs as root, resets its capability bounding set to the full kernel set,
and does not apply filesystem or namespace protections. Consequently, this
stage produces genuine unrestricted host UID 0 rather than a constrained
flag-reading helper. The implementation is in
[host/supervisor.py](host/supervisor.py) and
[host/relay-supervisor.service](host/relay-supervisor.service). This is an
intentional, dangerous challenge configuration; the installer requires an
explicit acknowledgement, and a solved VM must be destroyed and recreated.

### Build Phase 7: Integrate, Package, and Verify the Chain

Once the stages were implemented separately, the release was assembled around
explicit trust and file boundaries:

- `compose.yaml` defines the five containers, internal networks, resource
  limits, read-only filesystems, dropped capabilities, and the exact public
  Nginx mount for the Worker artifact.
- `db/init/002-schema.sql.in` creates separate database roles and APIs, then
  revokes direct service-role access before granting only the required
  functions.
- The host services install the backend fixture, firewall, root Supervisor,
  and transient Worker lifecycle.
- `scripts/install.sh` builds the Worker, creates fresh secrets, installs
  allowlisted runtime files, configures the host, and runs hardening checks.
- `scripts/verify-hardening.sh` checks container identities, network
  publication, database grants, marker permissions, Worker protections, SSH,
  firewall rules, and the Supervisor's intentionally unrestricted mode.
- Unit, integration, negative-path, and full-chain tests check local behavior
  and the deployed boundaries. Tests that perform the final root race must run
  only on a disposable VM prepared for destruction afterward.

The release process is intentionally separate from the player attack. The
organizer builds and verifies a complete bundle; the player receives only the
approved target information and any explicitly designed initial clue/artifact.
Repository test files and exploit helpers are validation and organizer tools,
not files installed into `/opt/relayforge` or the Web image. The exact installed
allowlists are recorded below in the deployment portion of this guide.

This narrative describes the checked-in construction. A source excerpt or
passing local test does not prove that a particular EC2 instance is running
those exact bytes. Deployment-specific claims require the installer
verification and external acceptance results to be recorded separately.

### Stage Markers and Validation

The three stage files indicate the privilege boundary reached: Web UID 65532,
host `relay`, and host UID 0. They are explanatory breadcrumbs, not scoring
flags or proof by themselves. The generated scoring flag remains
`/var/lib/relayforge/flag/root.txt`, readable only by root.

The setup and verification scripts install the marker files with distinct
ownership and modes, keep the Web container away from host stage files, and
verify that `relay` can read Stage 2 but not Stage 3 or the flag. The source
tests exercise the parser decisions, Worker protocol and frame assumptions,
Supervisor gates, and pathname replacement. Local tests establish behavior of
the checked-in implementation; only the deployment checks and an authorized
external run establish that the target instance is configured as intended.
The full root-chain acceptance test intentionally obtains host UID 0 and should
be run only when the operator is prepared to destroy and recreate that VM.

## 1. Required files

Distribute these two files together:

```text
RelayForge-Responsibilities-Flask-v1.zip
RelayForge-Responsibilities-Flask-v1.zip.sha256
```

Build and distribute the release from the authoritative DaBox repository root.
Do not mix in an older extraction, teammate prototype, or historical
comparison directory.

## 2. Create the Windows VM

Recommended practical allocation for the five containers, native build, and
host services:

```text
Guest OS:       Ubuntu Server 24.04.x LTS
Architecture:   AMD64 / x86-64
CPU:            2 virtual CPUs
RAM:            4 GB
Disk:           25 GB or more, dynamically allocated is acceptable
Network:        bridged/external switch
```

Bridged/external networking gives the VM its own reachable LAN IPv4 address.
That is the simplest arrangement because a running Worker uses a dynamic port
from `25000-25099`. Plain NAT is possible only if SSH 22, HTTPS 443, and the
whole Worker range are forwarded to the VM.

### Hyper-V on Windows Pro/Enterprise

1. Enable **Hyper-V** in “Turn Windows features on or off,” then reboot.
2. In Hyper-V Manager, open **Virtual Switch Manager** and create an
   **External** switch attached to the Windows adapter used for the LAN.
3. Create a **Generation 2** VM named `RelayForge-Ubuntu`.
4. Assign 4096 MB startup memory and two virtual processors.
5. Create a dynamically expanding VHDX of at least 25 GB.
6. Attach the Ubuntu Server 24.04 AMD64 ISO to the virtual DVD drive.
7. Connect the External switch.
8. Under Firmware/Security, use the **Microsoft UEFI Certificate Authority**
   Secure Boot template. If the ISO does not boot, disable Secure Boot for
   this disposable VM and retry.
9. Put the DVD/ISO above the disk in the first-boot order and start the VM.

### VirtualBox on Windows Home or Pro

1. Create a new VM with type **Linux** and version **Ubuntu (64-bit)**.
2. Assign 4096 MB RAM and two processors.
3. Create a dynamically allocated VDI of at least 25 GB.
4. Attach the Ubuntu Server 24.04 AMD64 ISO under Storage.
5. Under Network, set Adapter 1 to **Bridged Adapter** and select the Windows
   Ethernet/Wi-Fi adapter that actually reaches the LAN.
6. Start the VM.

If a managed Wi-Fi network blocks bridged guests, use a permitted lab LAN,
Hyper-V External switch, or a two-adapter design with one NAT adapter for
downloads and one host-only adapter for Windows-to-VM testing. In the latter
case, the host-only interface is the RelayForge `PUBLIC_IFACE`.
Disconnect or account for any Windows VPN that changes the source address or
route between the tester and VM.

## 3. Ubuntu Server installer selections

Download the official **64-bit PC (AMD64) server install image** for Ubuntu
Server 24.04 LTS. In the text installer, use these selections:

1. **Language:** the team's preferred language; English is recommended for
   identical logs.
2. **Installer update:** accept the update if offered.
3. **Keyboard:** select the actual keyboard layout.
4. **Installation type:** select normal **Ubuntu Server**, not a desktop.
5. **Network:** leave the bridged/external interface on DHCP. Record its IPv4
   address. Do not continue until it has network access.
6. **Proxy:** leave blank unless the organisation requires one.
7. **Mirror:** retain the default Ubuntu mirror unless the organisation
   supplies a mirror.
8. **Storage:** select **Use an entire disk**, choose the VM's virtual disk,
   and keep the guided LVM default. Do not enable disk encryption for this
   disposable lab VM because it prevents unattended reboot.
9. **Profile:** choose a hostname such as `relayforge-vm`; create a lowercase
   administrator such as `rfadmin`; use a temporary strong password.
10. **Ubuntu Pro:** skip it for the disposable lab.
11. **SSH:** enable **Install OpenSSH server**. Importing a public key is
    optional because the next section installs one explicitly.
12. **Featured server snaps:** select none.
13. Finish installation, reboot, and detach/eject the ISO when prompted.

Do not clone an already-installed RelayForge VM for multiple simultaneous
hosts on the same LAN. Clone the clean Ubuntu snapshot first, then give each
VM a unique hostname and IP before installing RelayForge.

## 4. First boot and SSH key

At the VM console:

```bash
sudo apt-get update
sudo apt-get full-upgrade -y
sudo reboot
```

After reboot, confirm the exact target:

```bash
uname -m
dpkg --print-architecture
. /etc/os-release
printf '%s %s\n' "$ID" "$VERSION_ID"
hostname -I
```

Expected values include:

```text
x86_64
amd64
ubuntu 24.04
```

On Windows PowerShell, generate a key if the tester does not already have one:

```powershell
ssh-keygen -t ed25519
```

Copy it to the Ubuntu account, replacing both placeholders:

```powershell
Get-Content "$env:USERPROFILE\.ssh\id_ed25519.pub" |
  ssh <admin-user>@<vm-ip> "umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys"
```

Prove that key-only login works before RelayForge hardens SSH:

```powershell
ssh -o PasswordAuthentication=no <admin-user>@<vm-ip>
```

Create a hypervisor snapshot named `clean-ubuntu-key-ready` now. The guest
firewall keeps key-only SSH source-unrestricted, but the console remains the
recovery path for a wrong interface or an external firewall problem.

## 5. Verify and upload the release on Windows

Keep the ZIP and its checksum in the same PowerShell directory:

```powershell
$Zip = ".\RelayForge-Responsibilities-Flask-v1.zip"
$Checksum = "$Zip.sha256"
$Expected = ((Get-Content $Checksum -Raw) -split '\s+')[0].ToLowerInvariant()
$Actual = (Get-FileHash $Zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Actual -ne $Expected) { throw "RelayForge ZIP checksum mismatch" }
"PASS: ZIP checksum $Actual"
```

Upload both files:

```powershell
scp $Zip $Checksum <admin-user>@<vm-ip>:~/
```

On Ubuntu:

```bash
sudo apt-get install -y unzip python3
RF_RELEASE_ZIP=$(readlink -f RelayForge-Responsibilities-Flask-v1.zip)
RF_RELEASE_SHA=$(readlink -f RelayForge-Responsibilities-Flask-v1.zip.sha256)
sha256sum -c "$RF_RELEASE_SHA"
RF_RELEASE_STAGE=$(mktemp -d /tmp/relayforge-release.XXXXXX)
unzip -q "$RF_RELEASE_ZIP" -d "$RF_RELEASE_STAGE"
cd "$RF_RELEASE_STAGE/RelayForge-Responsibilities-Flask-v1"
python3 tests/verify-release-bundle.py "$RF_RELEASE_ZIP"
python3 tests/check_shared_snapshot.py
python3 tests/check_integrated_stage.py
```

All four verifications must pass before installation.

Always create a new extraction directory. Never rebuild or reinstall from an
older `/tmp/relayforge-release.*` tree: an old tree can silently reinstall an
obsolete Worker even when the ZIP in the home directory is current.

## 6. Optional disposable preflight

This phase validates the packaged Docker build contexts, Flask/DB path, native
Worker, tunnel, intentional vulnerability, and systemd unit definitions
without installing the host stack.

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential ca-certificates docker.io docker-compose-v2 openssl python3
sudo systemctl enable --now docker.service
sudo usermod -aG docker "$USER"
```

Log out and reconnect so Docker-group membership takes effect, then run:

```bash
docker info --format '{{.Architecture}}'
./tests/run-local.sh
./tests/run-container-integration.sh
./tests/run-endpoint-integration.sh
./tests/test_systemd_units.sh
python3 tests/supervisor_systemd_integration.py
```

The Docker architecture must be `x86_64` or `amd64`; none of these commands
should print `FAIL`. The systemd integration should run, not print the ARM-host
skip message. The disposable suites remove their test containers and volumes.
Membership in the `docker` group is host-root-equivalent; it is acceptable for
the VM administrator during this disposable preflight, but never grant it to a
player or service identity and remove it when it is no longer needed.
Run this endpoint preflight before the full installation because the installed
`relay-backend.service` later owns loopback port 19001. Do not install Docker
from Snap, use rootless Docker, enable user-namespace remapping, or pre-create a
different `/etc/docker/daemon.json`; those modes conflict with the host-bound
deployment checks.

## 7. Determine the installation values

Connect directly from the Windows tester to Ubuntu over IPv4 SSH. On Ubuntu:

```bash
PUBLIC_IFACE=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
ADMIN_USER=$(id -un)
printf 'PLAYER_CIDR=0.0.0.0/0\nPUBLIC_IFACE=%s\nADMIN_USER=%s\n' \
  "$PUBLIC_IFACE" "$ADMIN_USER"
```

The standard deployment uses `PLAYER_CIDR=0.0.0.0/0`, allowing any IPv4 player
to reach HTTPS and temporary Worker ports. This is suitable only for a
disposable public CTF instance with no real data or privileged IAM role. A
private event may instead use one canonical organisation or VPN CIDR; the
installer accepts one Player CIDR, not comma-separated lists.

The Ubuntu guest always accepts key-only SSH on `PUBLIC_IFACE`, independently
of `PLAYER_CIDR`. An AWS Security Group is a separate firewall: to match this
public configuration it must allow TCP 22, 443, and 25000–25099 from
`0.0.0.0/0`. Do not expose 19001, 5432, or 8080. Opening SSH globally makes
the PEM key the administrative security boundary, so never share or commit it.

Record the VM address reached through the selected interface:

```bash
VM_IP=$(ip -4 -o addr show dev "$PUBLIC_IFACE" scope global | awk '{split($4,a,"/"); print a[1]; exit}')
printf 'VM_IP=%s\n' "$VM_IP"
```

Use the bundled endpoint for the first acceptance run:

```text
RELAY_ENDPOINT_HOST=127.0.0.1
RELAY_ENDPOINT_PORT=19001
```

That endpoint is installed as the host `relay-backend.service`. It must remain
private; players connect through a Worker, not directly to port 19001.

## 8. Install the complete host

Keep the VM console or a second SSH session open. Substitute the values printed
in the previous section:

```bash
sudo ./scripts/install.sh \
  --acknowledge-unrestricted-root \
  --player-cidr 0.0.0.0/0 \
  --public-interface "$PUBLIC_IFACE" \
  --admin-user "$ADMIN_USER" \
  --endpoint-host 127.0.0.1 \
  --endpoint-port 19001
```

The installer downloads Ubuntu packages, builds the native Worker, generates
database passwords, an Ed25519 signing key, a Flask secret and a self-signed
TLS certificate, pulls/builds the five containers, installs the systemd units,
applies the firewall/SSH policy, starts the stack, and runs host verification.

It also reconciles the RelayForge-owned installed footprint from explicit
allowlists. `/opt/relayforge/app` receives only Compose and the build inputs
used by nginx, Control, PostgreSQL, and Web; repository tests, attack helpers,
and READMEs stay in the release tree. `/opt/relayforge/runtime` contains the
four Python host programs and five supported lifecycle scripts, while
`/opt/relayforge/bin` contains only `relay-worker`. The installer removes the
exact obsolete `relay-cleanup.{service,timer}`, `relay-rotate.{service,timer}`,
and permanent `relay-worker.service` units. It also removes the one recognized
bounded-root Supervisor override after moving its useful runtime-directory
preservation into the canonical unit. Any other Supervisor drop-in causes a
fail-closed stop. The canonical service explicitly resets its capability
bounding set to the full kernel set. It does not delete home files,
arbitrary `/tmp` entries, foreign containers, images or volumes, OS/AWS
services, secrets, flags, active transient Worker state, or the PostgreSQL
volume. Here, “essentials only” means this bounded RelayForge footprint—not
stripping a normal Ubuntu installation.

The installer also copies the version-controlled
`config/60-relayforge-sysctl.conf` to
`/etc/sysctl.d/60-relayforge.conf`. Make lasting sysctl changes in the project
file as well as on the host, or a later installation will replace them.

RelayForge expects these runtime ownership boundaries:

```text
/etc/relayforge/job-signing.pub       root:root            0444
/var/lib/relayforge/workers           root:root            0711
/var/lib/relayforge/stages            root:root            0711
/var/lib/relayforge/stages/STAGE_2_WORKER.txt root:relayforge-ipc 0440
/var/lib/relayforge/stages/STAGE_3_ROOT.txt   root:root           0400
/var/lib/relayforge/flag/root.txt     root:root            0600
/run/relayforge/supervisor.sock       root:relayforge-ipc  0660
```

The Web image separately contains `/opt/relayforge/web/STAGE_1_WEB.txt` as
`root:root` mode `0444`. See `STAGE_MARKERS.md`; these are explanatory markers,
while `root.txt` is the generated secret.

Supervisor dynamically recreates the socket and repairs the Worker-state
parent. The main `/etc/ssh/sshd_config` may safely be root-owned mode `0600` or
`0644`; RelayForge manages its root-owned mode-`0644` policy drop-in at
`/etc/ssh/sshd_config.d/60-relayforge-hardening.conf` and verifies the effective
SSH policy.

Do not rerun the installer with a different endpoint against its existing
database volume. Restore the clean snapshot or explicitly reset/redeploy the
disposable VM when changing the endpoint.

### Updating an existing installation

Use the same recorded player CIDR, public interface, administrator, and endpoint
values, then rerun the installer from a newly verified and newly extracted
release. If the candidate Worker bytes differ, the installer refuses to begin
the upgrade while a transient Worker is active. Wait for its bounded expiry or
cancel it during the maintenance window, then rerun. When the Worker bytes are
unchanged, active transient Workers and state are preserved:

```bash
sudo systemctl list-units --state=running --type=service 'relay-worker-*'
sudo ./scripts/install.sh \
  --acknowledge-unrestricted-root \
  --player-cidr 0.0.0.0/0 \
  --public-interface "$PUBLIC_IFACE" \
  --admin-user "$ADMIN_USER" \
  --endpoint-host 127.0.0.1 \
  --endpoint-port 19001
sudo strings /opt/relayforge/bin/relay-worker | grep -E 'HTTP/1\.1|/relay/'
```

Both Worker protocol strings must be present. The installer prints the deployed
Worker SHA-256, recreates the edge container, and the hardening verifier proves
that the public download is byte-identical to the installed executable. Create
a new portal request after the update for functional acceptance.

To change a public deployment back to one trusted player network without
reinstalling:

```bash
sudo /opt/relayforge/runtime/configure-firewall.sh \
  198.51.100.0/24 "$PUBLIC_IFACE"
```

## 9. Verify the installed host

On Ubuntu:

```bash
sudo /opt/relayforge/runtime/verify-hardening.sh
sudo systemctl is-active docker.service relay-backend.service \
  relay-supervisor.service relayforge-firewall.service relayforge-stack.service
sudo docker compose --project-directory /opt/relayforge/app \
  --env-file /etc/relayforge/compose.env ps
python3 - <<'PY'
import ssl, urllib.request
assert urllib.request.urlopen("http://127.0.0.1:19001/health", timeout=5).read() == b"ok\n"
context = ssl._create_unverified_context()
assert urllib.request.urlopen("https://127.0.0.1/healthz", context=context, timeout=5).read() == b"ok\n"
print("PASS: private endpoint and HTTPS edge are healthy")
PY
```

Acceptance requires zero deployment-verification failures, five healthy
containers, all listed host services active, and both health requests
succeeding. Verification also checks the Stage 1/2/3 marker boundaries, exact
managed runtime trees, and absence of the five legacy units.

For a host-local functional run, use:

```bash
./tests/run-vm.sh https://127.0.0.1
```

This proves both real Worker paths, but deliberately skips the external-port
isolation probes because the private endpoint is supposed to be reachable on
the host's own loopback interface. Run Section 11 from the player machine to
verify that ports 5432, 8080, and 19001 are unreachable externally.

## 10. Test the user path from Windows

Open this URL from the Windows host:

```text
https://<vm-ip>/login
```

The certificate is intentionally self-signed, so a browser warning is expected
in this lab. Log in with:

```text
username: guest
password: guest-relay-2026
```

Select `archive-echo`, retain service `echo`, choose 30-420 seconds, and submit.
The portal redirects to the request's status page and refreshes while Access,
Dispatcher, and Supervisor provision it. Once approved, select **Open private
endpoint**. The temporary link uses a Worker port in `25000-25099` and displays
`RelayForge endpoint reached` plus a fake flag from the loopback-only server.
It stops working after cancellation or expiry. The link uses plain HTTP because
TLS terminates only on the portal; treat its embedded short-lived token as a
bearer credential.

While it is running, prove that the host created an actual Worker:

```bash
sudo systemctl list-units --type=service 'relay-worker-*'
sudo ss -ltnp | grep -E ':250[0-9]{2}'
```

The `relay-worker-<job-uuid>.service` unit and listening port disappear after
the requested duration or cancellation. That bounded lifetime is expected.

## 11. Complete external acceptance from Windows

Install Python 3 on Windows and extract the same release ZIP locally. These
two clients use only the Python standard library. In PowerShell from the
extracted release directory:

```powershell
$Target = "https://<vm-ip>"
py -3 tests\negative_paths.py $Target
py -3 attacks\full_chain.py $Target
```

`negative_paths.py` launches a real safe Worker, rejects wrong CLI and browser
tokens, opens the browser URL, establishes `CONNECT`, reads the bundled HTTP
endpoint through both paths, rejects shortcut attacks, and cancels the Worker.
`full_chain.py` verifies the authenticated Flask foothold, restricted
database RPC, Access signature, Dispatcher, real Worker tunnel and intended
Worker/Supervisor challenge chain. It succeeds only after printing an
`ROOT_UID=0` proof and an `RF{...}` flag read through that root process.

The release is fully accepted only when all of these are true:

1. Release checksum, manifest, stage, and ZIP verifier pass.
2. Optional disposable suites contain no failures.
3. Installed verification reports zero failures and confirms both the hardened
   Worker boundary and the deliberately unrestricted Supervisor boundary.
4. A real `relay-worker-<uuid>.service` and port appear during a request.
5. Windows `negative_paths.py` passes its actual tunnel test.
6. Windows `full_chain.py` proves UID 0 and prints the flag.

## 12. Troubleshooting

- **`uname -m` is `aarch64`:** the wrong ISO/architecture was installed. Create
  an AMD64 VM.
- **Browser cannot reach HTTPS:** confirm bridged/external networking, the VM
  IPv4, `PLAYER_CIDR`, `PUBLIC_IFACE`, client-to-VM routing, and the AWS
  Security Group. Use an explicit `https://` URL.
- **Login works but Worker connection times out:** ports `25000-25099` are not
  reaching the VM or the player source is outside `PLAYER_CIDR`.
- **Browser reports `ERR_INVALID_HTTP_RESPONSE`:** the host may have an old
  raw-protocol-only Worker even while all five containers are healthy. Check
  `sudo strings /opt/relayforge/bin/relay-worker | grep -E 'HTTP/1\.1|/relay/'`.
  If either marker is absent, reinstall from a newly verified, freshly
  extracted release, cancel or wait out the existing Worker, and create a new
  request. Do not rebuild from a previously extracted `/tmp` directory.
- **SSH times out:** this release does not source-filter SSH inside Ubuntu.
  Confirm the EC2/VM is running, its address is current, TCP 22 is permitted by
  the AWS/hypervisor firewall, and `PUBLIC_IFACE` names the ingress interface.
- **Port 19001 is unreachable from Windows:** this is correct. It is a private
  endpoint reached only through an authenticated Worker.
- **Worker disappears:** check the requested 30-420 second lifetime and
  cancellation status; Workers are deliberately transient.
- **Certificate warning:** expected for the generated self-signed certificate.
- **A service fails:** collect `sudo systemctl status <unit>` and
  `sudo journalctl -u <unit> -n 200 --no-pager` before resetting the VM.

## 13. Optional footprint audit and bounded housekeeping

The installer removes unsupported files from its three managed `/opt` trees
and the exact legacy units. Supervisor reaps valid expired Worker state, and
Compose starts with `--remove-orphans`. Inspect before any further cleanup:

Inspect before removing anything:

```bash
df -h /
sudo docker system df
sudo systemctl list-units --all --type=service 'relay-worker-*'
sudo find /tmp -maxdepth 1 -type d \
  \( -name 'relayforge-release.*' -o -name 'relayforge-deploy.*' \
     -o -name 'relayforge-worker-fix.*' \) -print
```

After confirming that no Worker is active, clearing historical failed-unit
status is safe and cosmetic:

```bash
sudo systemctl reset-failed 'relay-worker-*.service'
```

Old, positively identified extraction/build directories may be removed one at
a time after the verified ZIP and checksum are retained. The installer does
not use broad `/tmp` globs or erase administrator home files, and it does not
infer that an unlabelled container, image, volume, AWS agent, or Ubuntu package
is disposable. Do not manually remove `/opt/relayforge`, `/etc/relayforge`,
`/var/lib/relayforge`, or any RelayForge Docker volume. Do not use broad
`apt autoremove`/package purges, `docker system prune -a --volumes`,
`docker volume prune`, or `docker compose down --volumes` as housekeeping.

`sudo /opt/relayforge/runtime/reset-lab.sh --yes` is a destructive challenge
reset, not cleanup: it removes the PostgreSQL volume and Worker state and
rotates the flag. It is not trustworthy remediation after a player has reached
unrestricted root; destroy and recreate that VM from a known-good image.

## Official platform references

- Ubuntu Server basic installation:
  <https://ubuntu.com/server/docs/tutorial/basic-installation/>
- Ubuntu Server installation documentation:
  <https://ubuntu.com/server/docs/how-to/installation/>
- Hyper-V VM creation:
  <https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/create-a-virtual-machine-in-hyper-v>
- Hyper-V Generation 2 and Ubuntu support:
  <https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/should-i-create-a-generation-1-or-2-virtual-machine-in-hyper-v>
- VirtualBox bridged networking:
  <https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/networkingdetails.html>
