# RelayForge EC2 recovery and in-place upgrade guide

This runbook brings the existing Group 30 EC2 deployment back to a known-good
state without deleting its PostgreSQL volume, generated secrets, or root flag.
It applies to the bounded Flask variant in this directory.

Commands are divided between the administrator's computer and the EC2 SSH
session. Run each command only on the machine named by its section.

## Current EC2 assessment

The read-only audit on 24 September 2026 found:

| Observation | Meaning | Required action |
|---|---|---|
| All five Compose containers were healthy | nginx, Flask, PostgreSQL, Access, and Dispatcher remained operational | Preserve the Docker volume; do not reset the lab |
| `relayforge-stack.service` was `failed` | A previous Compose start failed, and systemd retained the result even though the containers later became healthy | Repair the key permission and restart through the installer |
| `job-signing.pem` was mode `0644` | The file-level mode was broader than the enforced signing-key contract | Restore `root:relayforge-signing` mode `0440` |
| `relay-cleanup.timer` and `relay-rotate.timer` were enabled | Obsolete units from the earlier rotating design were invoking scripts that no longer exist | Disable those timers once |
| The Worker contained `HTTP/1.1` and `/relay/` | The installed binary supported both browser forwarding and the challenge protocol | Do not replace it from an old extraction |
| No Worker unit was active | No live participant session needed to be interrupted | Maintenance could proceed |
| The home-directory ZIP was older than the latest local release | An old ZIP or `/tmp` tree could reinstall stale code | Upload and freshly extract the current release |
| Root filesystem usage was about 29 percent | There was no storage emergency | Do not run broad Docker pruning |

This is an in-place repair and upgrade, not a reset.

The active deployment lives in:

```text
/opt/relayforge       installed application, Worker, and host runtime
/etc/relayforge       generated configuration, TLS material, and signing keys
/var/lib/relayforge   Worker state and generated root flag
Docker volume         persistent PostgreSQL data
```

Old ZIPs, exports, `supervisor.py.fixed`, and similar home-directory files are
inactive artifacts. They do not need to be deleted to repair the application.

## What each change does

| Change | Why it is needed | What it changes |
|---|---|---|
| Disable `relay-cleanup.timer` and `relay-rotate.timer` | They belong to the old rotating-Worker experiment. The current Supervisor owns the finite 30–420 second Worker lifecycle. | Stops obsolete jobs from repeatedly failing. It does not remove project data. |
| Change the signing private key from `0644` to `0440` | The file-level mode granted an unnecessary “other read” bit and failed the least-privilege contract. | Root and the dedicated signing group receive read bits; no permission bits are granted to other identities. |
| Verify the new ZIP and use a new extraction directory | A reused tree can contain an old Worker or manual partial fixes. | Makes the ZIP and its manifest the only installation source. |
| Rerun `install.sh` | Reconciles application files, Worker binary, units, containers, firewall, and SSH policy. | Briefly interrupts the portal while preserving the database volume, flag, keys, certificate, and generated secrets. |
| Clear historical failed transient units | Old failed tests remain visible in systemd after they finish. | Removes only cosmetic failure records; it does not delete a live Worker. |
| Run hardening and end-to-end tests | Healthy containers alone do not prove the host Worker tunnel or flag chain. | Verifies both the security boundaries and actual challenge behavior. |

After a successful start, `relayforge-stack.service` should be
`active (exited)`. It is a successful `Type=oneshot` unit with
`RemainAfterExit=yes`; `exited` does not mean the containers stopped.

## Safety rules

- Keep the current SSH session open and use a second terminal for the upload.
- Do not print or share `/etc/relayforge/compose.env`; it contains passwords
  and the Flask session secret.
- Use the recorded endpoint `127.0.0.1:19001`. The installer rejects an
  endpoint change against the existing persistent database.
- Cancel or wait for any active Worker before replacing its executable.
- Do not remove `/opt/relayforge`, `/etc/relayforge`, or
  `/var/lib/relayforge`.
- Do not run any of these as housekeeping:

```bash
sudo docker compose down --volumes
sudo docker volume prune
sudo docker system prune -a --volumes
sudo /opt/relayforge/runtime/reset-lab.sh --yes
```

The Docker commands can destroy PostgreSQL data. `reset-lab.sh` deliberately
creates a fresh challenge and rotates the flag.

## 1. Keep a recovery session open

From the administrator's computer:

```bash
ssh -i ./ICT2212-AY26-T1-student30.pem student30@18.216.228.46
```

Why: RelayForge reapplies host firewall and SSH settings. An already
authenticated terminal remains available for diagnosis during the short
restart window.

The earlier `Can't assign requested address` SSH message was a client-side
temporary socket error. It was not evidence that RelayForge had deleted the
EC2 or its files.

## 2. Record the non-secret deployment settings

On the EC2:

```bash
ip -4 route show default

sudo sed -n \
  -e '/^PLAYER_CIDR=/p' \
  -e '/^PUBLIC_IFACE=/p' \
  -e '/^ENDPOINT_HOST=/p' \
  -e '/^ENDPOINT_PORT=/p' \
  /etc/relayforge/firewall.env

sudo grep -E '^(RELAY_ENDPOINT_HOST|RELAY_ENDPOINT_PORT)=' \
  /etc/relayforge/compose.env

sudo grep '^ADMIN_USER=' /etc/relayforge/install.state
```

Expected values for this EC2 are:

```text
PLAYER_CIDR=0.0.0.0/0
PUBLIC_IFACE=ens5
ADMIN_USER=student30
RELAY_ENDPOINT_HOST=127.0.0.1
RELAY_ENDPOINT_PORT=19001
```

`0.0.0.0/0` means Ubuntu permits HTTPS and temporary Worker traffic from any
IPv4 source. It does not modify the AWS Security Group; AWS must also allow
the relevant ports.

## 3. Confirm that no Worker is active

```bash
sudo systemctl list-units \
  --state=running \
  --type=service \
  'relay-worker-*'
```

No matching `relay-worker-*` service row is expected during maintenance
(systemd may still print headings or a footer). If a Worker appears, close it
through the portal or wait for its requested lifetime to expire. Replacing an
executable does not update an already running process because Linux continues
executing its loaded image.

## 4. Upload the authoritative release from the administrator's computer

Open a second terminal on the Mac:

```bash
cd "/Users/pengsbook/Documents/Schoolwork (SIT)/Y1T2/ICT2212"
chmod 600 ICT2212-AY26-T1-student30.pem

ssh -i ./ICT2212-AY26-T1-student30.pem \
  student30@18.216.228.46 \
  'mkdir -p "$HOME/relayforge-upgrade-20260924"'

scp -i ./ICT2212-AY26-T1-student30.pem \
  relayforge-lab/responsibilities/release/RelayForge-Responsibilities-Flask-v1.zip \
  relayforge-lab/responsibilities/release/RelayForge-Responsibilities-Flask-v1.zip.sha256 \
  student30@18.216.228.46:~/relayforge-upgrade-20260924/
```

What this means:

- `chmod 600` makes the PEM readable and writable only by its owner. OpenSSH
  rejects private keys with broad permissions.
- `scp -i` authenticates with that PEM and transfers the two release files.
- The separate upgrade directory preserves the old ZIP and teammate exports.
- The `.sha256` sidecar identifies the exact ZIP that should be installed.
- Uploading does not change the running application.

Windows PowerShell equivalent:

```powershell
$Key = ".\ICT2212-AY26-T1-student30.pem"
icacls $Key /inheritance:r
icacls $Key /grant:r "$($env:USERNAME):(R)"

ssh -i ".\ICT2212-AY26-T1-student30.pem" `
  student30@18.216.228.46 `
  "mkdir -p ~/relayforge-upgrade-20260924"

scp -i ".\ICT2212-AY26-T1-student30.pem" `
  ".\relayforge-lab\responsibilities\release\RelayForge-Responsibilities-Flask-v1.zip" `
  ".\relayforge-lab\responsibilities\release\RelayForge-Responsibilities-Flask-v1.zip.sha256" `
  "student30@18.216.228.46:~/relayforge-upgrade-20260924/"
```

The two `icacls` commands remove inherited Windows ACL entries and grant the
current Windows account read access. Use them if Windows OpenSSH reports that
the private key permissions are too open. They change only the local PEM file,
not the EC2 account or server.

## 5. Verify and freshly extract the uploaded ZIP

```bash
cd ~/relayforge-upgrade-20260924
sha256sum -c RelayForge-Responsibilities-Flask-v1.zip.sha256
```

Expected:

```text
RelayForge-Responsibilities-Flask-v1.zip: OK
```

Do not install if this fails. It indicates an incomplete transfer or a ZIP and
sidecar from different builds.

Create a new extraction directory every time:

```bash
RF_RELEASE_ZIP=$(readlink -f RelayForge-Responsibilities-Flask-v1.zip)
RF_RELEASE_STAGE=$(mktemp -d /tmp/relayforge-release.XXXXXX)

unzip -q "$RF_RELEASE_ZIP" -d "$RF_RELEASE_STAGE"
cd "$RF_RELEASE_STAGE/RelayForge-Responsibilities-Flask-v1"

python3 tests/verify-release-bundle.py "$RF_RELEASE_ZIP"
python3 tests/check_shared_snapshot.py
python3 tests/check_integrated_stage.py
```

The checks have different purposes:

1. `sha256sum -c` proves the transferred ZIP matches its sidecar.
2. `verify-release-bundle.py` rejects unsafe paths, symlinks, secret material,
   missing files, CRC damage, and archive-manifest mismatches.
3. `check_shared_snapshot.py` verifies every extracted source file against
   `MANIFEST.sha256`.
4. `check_integrated_stage.py` checks that the complete deployable Flask
   integration is present.

A fresh directory matters because the installer compiles
`worker/relay-worker.c` from its source tree. Reusing an old `/tmp` extraction
can silently reinstall an obsolete Worker even if a new ZIP is in the home
directory.

Do not make host or service changes until every command in this section passes.

## 6. Disable obsolete lifecycle units

On the EC2:

```bash
sudo systemctl disable --now \
  relay-cleanup.timer \
  relay-rotate.timer 2>/dev/null || true

sudo systemctl stop \
  relay-cleanup.service \
  relay-rotate.service 2>/dev/null || true

sudo systemctl reset-failed \
  relay-cleanup.service \
  relay-cleanup.timer \
  relay-rotate.service \
  relay-rotate.timer 2>/dev/null || true
```

Why:

- `relay-rotate.timer` belongs to the separate seven-minute Worker design.
- `relay-cleanup.timer` calls an old script; current Supervisor reaps expired
  Workers itself.
- `disable --now` stops future activation and stops the timers now.
- `stop` ends an old service if it happens to be running.
- `reset-failed` clears only the historical red status.

The old unit files may remain disabled under `/etc/systemd/system`. Keeping
them is reversible and does not affect the bounded deployment.

## 7. Repair the signing private key boundary

```bash
sudo chown root:relayforge-signing \
  /etc/relayforge/secrets/job-signing.pem

sudo chmod 0440 \
  /etc/relayforge/secrets/job-signing.pem

sudo stat -c '%U:%G %a %n' \
  /etc/relayforge/secrets/job-signing.pem
```

Expected result:

```text
root:relayforge-signing 440 /etc/relayforge/secrets/job-signing.pem
```

Verify that the running Access container retains its intended read access:

```bash
sudo docker compose \
  --project-directory /opt/relayforge/app \
  --env-file /etc/relayforge/compose.env \
  exec -T access \
  sh -c 'id; test -r /run/secrets/job-signing.pem && echo "PASS: signing key readable"'
```

`0440` sets owner-read and group-read, sets no “other” permissions, and sets no
write or execute bits. The root-only `0700` parent directories already prevent
ordinary host users from traversing to the key; the tighter file mode also
enforces the intended least-privilege boundary when Docker bind-mounts the
file into Access. Access receives the numeric `relayforge-signing` group
through Compose. Supervisor is configured with and uses only the public
verification key; Access performs the signing step.

The audited Access container used supplementary GID `985`, matching the host
signing group. Tightening `0644` to `0440` therefore removes the unnecessary
file-level other-read bit without breaking Access. The installer deliberately
rejects an existing private key with unsafe permissions, so this repair must
happen before step 8.

## 8. Run the in-place installer

From the fresh extracted directory:

```bash
sudo ./scripts/install.sh \
  --player-cidr 0.0.0.0/0 \
  --public-interface ens5 \
  --admin-user student30 \
  --endpoint-host 127.0.0.1 \
  --endpoint-port 19001
```

Argument meanings:

| Argument | Meaning on this EC2 |
|---|---|
| `--player-cidr 0.0.0.0/0` | Ubuntu permits portal and Worker traffic from any IPv4 source that AWS also allows. |
| `--public-interface ens5` | Public traffic arrives at the instance through `ens5`. |
| `--admin-user student30` | SSH hardening preserves key-only administration for this account. |
| `--endpoint-host 127.0.0.1` | The sample HTTP endpoint is host-local and not directly public. |
| `--endpoint-port 19001` | Workers may reach only this registered endpoint port. |

There is no separate `--admin-cidr` in this release. Ubuntu permits key-only
SSH on the public interface; the AWS Security Group separately decides which
sources can reach TCP 22. Anyone with the PEM can attempt administration, so
the PEM is the critical SSH credential.

The installer:

1. validates Ubuntu 24.04 AMD64 and the service identities;
2. installs the required Ubuntu packages;
3. updates `/opt/relayforge` from this verified source;
4. recompiles the native Worker with PIE, NX, stack protection, and full
   RELRO;
5. retains and validates the existing generated environment and keys;
6. reapplies sysctl, SSH, and firewall policy;
7. rebuilds the Web, Access, and Dispatcher images; and
8. restarts the backend, Supervisor, firewall, and five-container stack.

The PostgreSQL named volume remains intact. `init-challenge.sh` retains an
existing safe root flag unless explicitly invoked with `--rotate`. Expect
brief downtime because Docker and the application stack are restarted.

## 9. Clear historical transient-unit failures

```bash
sudo systemctl reset-failed \
  relay-cleanup.service \
  relay-cleanup.timer \
  relay-rotate.service \
  relay-rotate.timer \
  'relay-worker-*.service' \
  'test-worker*.service' 2>/dev/null || true
```

This removes records from earlier failed test or transient units. It does not
repair a current failure and does not delete Worker data. Do not reset an
unrelated AWS SSM Agent failure without diagnosing that service separately.

## 10. Verify the installed host

```bash
sudo systemctl status relayforge-stack.service --no-pager

sudo docker compose \
  --project-directory /opt/relayforge/app \
  --env-file /etc/relayforge/compose.env \
  ps

sudo /opt/relayforge/runtime/verify-hardening.sh

curl --fail http://127.0.0.1:19001/health
curl --fail --insecure https://127.0.0.1/healthz

sudo strings /opt/relayforge/bin/relay-worker | grep -F 'HTTP/1.1'
sudo strings /opt/relayforge/bin/relay-worker | grep -F '/relay/'
```

Expected results:

- the stack unit is `active (exited)`;
- exactly five containers are `Up` and `healthy`;
- hardening reports zero failures;
- both local health requests succeed; and
- Worker strings include both `HTTP/1.1` and `/relay/`.

Hardening proves permissions and isolation. It does not prove that the
intended vulnerability reaches the flag.

## 11. Run complete application acceptance

From the fresh release directory:

```bash
./tests/run-vm.sh https://127.0.0.1
```

This runs:

- `negative_paths.py`, which proves authentication, rejection behavior, a
  genuine browser/CONNECT tunnel, and cancellation; and
- `full_chain.py`, which exercises the intentional Web, database, Worker, and
  Supervisor vulnerabilities.

A complete pass prints a generated `RF{...}` value. Do not copy that value
into source control.

## 12. Test from a participant browser

Open:

```text
https://18.216.228.46/login
```

Credentials:

```text
Username: guest
Password: guest-relay-2026
```

The TLS warning is expected because this disposable lab uses a self-signed
certificate. Confirm the assigned IP before accepting it.

An approved request displays a URL resembling:

```text
http://18.216.228.46:25037/relay/<48-hex-token>/
```

The temporary Worker uses plain HTTP. Its port and token change for each
request and disappear on expiry or cancellation.

The AWS owner must permit the intended participant sources to reach:

```text
TCP 443          HTTPS portal
TCP 25000-25099 temporary Worker listeners
TCP 22           key-only administrator SSH
```

Do not expose TCP 19001, 5432, or 8080. Ubuntu commands cannot edit the AWS
Security Group. If local acceptance passes but a teammate times out, the
remaining boundary is probably AWS or the teammate's network.

Opening all three public ranges to `0.0.0.0/0` is acceptable only for a
disposable CTF instance with no sensitive data or privileged IAM role. It
makes possession of the PEM the primary SSH boundary.

## 13. Failure handling

Do not reset the database after an installation error. Collect evidence:

```bash
sudo systemctl status relayforge-stack.service --no-pager
sudo journalctl -u relayforge-stack.service -n 200 --no-pager
sudo journalctl -u relay-supervisor.service -n 200 --no-pager

sudo docker compose \
  --project-directory /opt/relayforge/app \
  --env-file /etc/relayforge/compose.env \
  ps -a

sudo docker compose \
  --project-directory /opt/relayforge/app \
  --env-file /etc/relayforge/compose.env \
  logs --tail=200

sudo stat -c '%U:%G:%a %n' \
  /etc/relayforge/secrets/job-signing.pem \
  /etc/relayforge/job-signing.pub \
  /var/lib/relayforge/flag/root.txt
```

Correct permission results are:

```text
root:relayforge-signing:440 /etc/relayforge/secrets/job-signing.pem
root:root:444              /etc/relayforge/job-signing.pub
root:root:600              /var/lib/relayforge/flag/root.txt
```

Correct the specific logged error and rerun the same verified installer with
the same endpoint values.

There is no automatic application-file rollback. If the new release proves
faulty, verify a previously known-good ZIP and rerun its `install.sh` with the
same player CIDR, interface, admin user, and endpoint values. That reinstalls
the older application files while retaining the PostgreSQL volume, generated
keys, certificate, and root flag. Do not use `docker compose down --volumes`
or `reset-lab.sh` as a rollback mechanism; those operations destroy or rotate
challenge state. If the AWS owner can take an EC2 snapshot before maintenance,
that provides the strongest whole-instance rollback because `install.sh` is
an in-place reconciliation rather than a transactional update.

If a browser reports `ERR_INVALID_HTTP_RESPONSE` on a Worker URL, verify the
Worker markers shown in step 10. Missing markers mean an obsolete binary was
installed from a stale tree.

## 14. Optional maintenance after acceptance

No filesystem or Docker cleanup is currently required. Preserve old teammate
exports until the team agrees they are unnecessary. Safe inspection commands
are:

```bash
df -h /
sudo docker system df
sudo systemctl --failed

sudo find /tmp -maxdepth 1 -type d \
  \( -name 'relayforge-release.*' \
     -o -name 'relayforge-deploy.*' \
     -o -name 'relayforge-worker-fix.*' \) \
  -print
```

Do not use a broad `rm -rf /tmp/relayforge-*` command. Identify any exact path
before removing it.

After application and attack acceptance both pass, install Ubuntu security
updates only in a planned maintenance window, preferably after the AWS owner
takes an EC2 snapshot. Package upgrades and a reboot are disruptive:

```bash
sudo apt-get update
sudo apt-get upgrade -y
test ! -e /var/run/reboot-required || sudo reboot
```

Repeat the service, container, and hardening checks after any reboot.
