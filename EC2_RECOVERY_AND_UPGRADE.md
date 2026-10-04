# RelayForge EC2 deployment, reconciliation, and recovery

> **Unrestricted-host-root challenge:** a successful player obtains real UID 0
> on the EC2 host. Use only a disposable, single-player instance with no IAM
> role, reusable credentials, valuable data, or other workloads. An in-place
> reinstall is convenient for testing but is not trusted recovery after anyone
> reaches the final stage; terminate and recreate the instance instead.

This runbook updates the assigned RelayForge EC2 from the authoritative DaBox
repository and supersedes the historical prototype-layout procedure.
The example host is `student30@18.216.228.46`; substitute the current address
if AWS changes it.

## What “clean” means

The installer owns a deliberately narrow footprint:

| Location | Reconciled content |
|---|---|
| `/opt/relayforge/app` | Compose plus the nginx, Control, database-init, and Web build inputs |
| `/opt/relayforge/runtime` | Four Python host programs and five supported lifecycle scripts |
| `/opt/relayforge/bin` | `relay-worker` only |
| `/etc/systemd/system` | Four current RelayForge units and no Supervisor override drop-in |

Every install removes unsupported files from those three `/opt` trees and
removes these five exact legacy units:

```text
relay-cleanup.service
relay-cleanup.timer
relay-rotate.service
relay-rotate.timer
relay-worker.service
```

The installer also removes the exact previously inventoried bounded-root
`/etc/systemd/system/relay-supervisor.service.d/override.conf`. That file kept
only five Linux capabilities and therefore prevented this variant from
delivering unrestricted host root. Its useful
`RuntimeDirectoryPreserve=yes` setting now lives in the canonical unit, which
also explicitly resets `CapabilityBoundingSet=~` to all capabilities supported
by the kernel. If the directory contains any other drop-in, installation stops
for manual review instead of deleting unknown administrator policy.

It preserves:

- `/etc/relayforge` secrets, TLS material, endpoint settings, and signing key;
- `/var/lib/relayforge` flag, stage markers, and transient Worker state;
- the `relayforge_postgres_data` Docker volume;
- active transient `relay-worker-<UUID>.service` units; and
- the current five-container Compose project.

It refuses to proceed while a foreign container is running. It never runs
`apt autoremove`, package-wide purges, Docker prune, volume deletion, home
directory cleanup, or `/tmp` wildcards. “Essentials only” means an exact
RelayForge-managed runtime on a normal Ubuntu/AWS host—not removal of Ubuntu,
SSH, SSM/cloud agents, or unknown administrator data.

## 1. Build and verify the release on the administrator Mac

From the repository:

```bash
cd "/Users/pengsbook/Documents/Schoolwork (SIT)/Y1T2/ICT2212/DaBox"

python3 tests/check_integrated_stage.py
python3 tests/test_python_syntax.py
python3 tests/test_supervisor.py
python3 tests/static_audit.py
bash -n scripts/*.sh tests/*.sh
./scripts/package-release.sh ..
python3 tests/verify-release-bundle.py \
  ../RelayForge-Responsibilities-Flask-v1.zip
```

Docker-backed and nested-systemd suites should also pass on an AMD64 Docker
host when available. The EC2 deployment verification and external acceptance
later in this guide are mandatory even when local Docker is unavailable.

The two upload artifacts are:

```text
../RelayForge-Responsibilities-Flask-v1.zip
../RelayForge-Responsibilities-Flask-v1.zip.sha256
```

## 2. Keep one SSH recovery session open

Protect the PEM, then connect:

```bash
cd "/Users/pengsbook/Documents/Schoolwork (SIT)/Y1T2/ICT2212"
chmod 600 ICT2212-AY26-T1-student30.pem
ssh -i ./ICT2212-AY26-T1-student30.pem student30@18.216.228.46
```

The PEM belongs only to administrators. Never give it to a player: this
account has passwordless sudo and Docker access, either of which is an
immediate host-root shortcut unrelated to the challenge.

Keep this terminal open. Use a second terminal for upload and deployment.

## 3. Read-only host preflight

On the EC2, record the current non-secret settings and workload boundary:

```bash
uname -m
. /etc/os-release
printf '%s %s\n' "$ID" "$VERSION_ID"

ip -4 route show default
sudo sed -n \
  -e '/^PLAYER_CIDR=/p' \
  -e '/^PUBLIC_IFACE=/p' \
  -e '/^ENDPOINT_HOST=/p' \
  -e '/^ENDPOINT_PORT=/p' \
  /etc/relayforge/firewall.env
sudo grep '^ADMIN_USER=' /etc/relayforge/install.state

sudo docker ps --format \
  'table {{.Names}}\t{{.Status}}\t{{.Label "com.docker.compose.project"}}'
sudo ss -ltnp
sudo systemctl list-units --all --type=service 'relay-worker-*'
```

Expected deployment values for this EC2 are:

```text
Architecture:        x86_64
Ubuntu:              24.04
PLAYER_CIDR:         0.0.0.0/0
PUBLIC_IFACE:        ens5
ADMIN_USER:          student30
ENDPOINT_HOST:       127.0.0.1
ENDPOINT_PORT:       19001
Compose project:     relayforge only
```

Stop if any running container is not labelled with Compose project
`relayforge`, if another service owns TCP 443, or if the endpoint differs from
the recorded database deployment. Resolve that ownership explicitly; do not
delete an unknown workload.

The installer preserves active Workers. A Worker already in memory continues
using its old binary until cancellation or expiry, so acceptance must create a
new request after the update.

## 4. Upload a freshly packaged release

From a second Mac terminal:

```bash
cd "/Users/pengsbook/Documents/Schoolwork (SIT)/Y1T2/ICT2212"

ssh -i ./ICT2212-AY26-T1-student30.pem \
  student30@18.216.228.46 \
  'install -d -m 0700 "$HOME/relayforge-upgrade"'

scp -i ./ICT2212-AY26-T1-student30.pem \
  RelayForge-Responsibilities-Flask-v1.zip \
  RelayForge-Responsibilities-Flask-v1.zip.sha256 \
  student30@18.216.228.46:~/relayforge-upgrade/
```

Upload the ZIP and checksum together. Uploading does not modify the running
stack.

## 5. Verify and extract once on the EC2

On the EC2:

```bash
cd ~/relayforge-upgrade
sha256sum -c RelayForge-Responsibilities-Flask-v1.zip.sha256

RF_RELEASE_STAGE=$(mktemp -d /tmp/relayforge-release.XXXXXX)
unzip -q RelayForge-Responsibilities-Flask-v1.zip -d "$RF_RELEASE_STAGE"
cd "$RF_RELEASE_STAGE/RelayForge-Responsibilities-Flask-v1"

python3 tests/verify-release-bundle.py \
  "$HOME/relayforge-upgrade/RelayForge-Responsibilities-Flask-v1.zip"
python3 tests/check_shared_snapshot.py
python3 tests/check_integrated_stage.py
```

All checks must pass. Never reinstall from an old `/tmp/relayforge-release.*`
directory; that is how an outdated Worker can reappear after the ZIP changes.

## 6. Repair only known pre-existing drift

The installer refuses an unsafe existing signing key instead of silently
blessing it. If inspection shows the known historical mode drift, confirm it
is a regular root-owned file inside the root-only secrets directory, then
restore the contract:

```bash
sudo stat -c '%F %U:%G %a %n' \
  /etc/relayforge/secrets \
  /etc/relayforge/secrets/job-signing.pem
sudo test ! -L /etc/relayforge/secrets/job-signing.pem
sudo test "$(sudo stat -c '%U' /etc/relayforge/secrets/job-signing.pem)" = root
sudo chown root:relayforge-signing \
  /etc/relayforge/secrets/job-signing.pem
sudo chmod 0440 /etc/relayforge/secrets/job-signing.pem
```

This is a repair for this inventoried lab host, not a generic response to a
leaked key. If untrusted users could have read the key, rebuild the disposable
instance and generate new secrets.

If the old host nginx package remains, first prove that it is the disabled
conflicting service and that no unrelated site needs it:

```bash
sudo systemctl is-active nginx.service || true
sudo dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' \
  nginx nginx-common nginx-core 2>/dev/null || true
```

On this dedicated challenge EC2, those positively identified nginx packages
may be removed because TLS is provided by the `relayforge-edge-1` container:

```bash
sudo systemctl disable --now nginx.service 2>/dev/null || true
sudo apt-get purge -y nginx nginx-common nginx-core
```

Do not generalize this into a package purge on another host.

## 7. Run the idempotent installer

From the freshly extracted release root:

```bash
PUBLIC_IFACE=$(ip -4 route show default | \
  awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
ADMIN_USER=$(id -un)

sudo ./scripts/install.sh \
  --acknowledge-unrestricted-root \
  --player-cidr 0.0.0.0/0 \
  --public-interface "$PUBLIC_IFACE" \
  --admin-user "$ADMIN_USER" \
  --endpoint-host 127.0.0.1 \
  --endpoint-port 19001
```

The installer stops only the services whose files it replaces, reconciles the
three managed trees, removes the five exact legacy units, builds/pulls the
stack, restores the firewall and SSH policy, and runs hardening verification.
The PostgreSQL volume, flag, secrets, and active Worker state remain intact.

`relayforge-stack.service` is a successful oneshot service, so
`active (exited)` is the expected state.

## 8. Verify installed footprint and health

```bash
sudo /opt/relayforge/runtime/verify-hardening.sh

sudo systemctl is-active \
  docker.service \
  relay-backend.service \
  relay-supervisor.service \
  relayforge-firewall.service \
  relayforge-stack.service

sudo docker compose \
  --project-directory /opt/relayforge/app \
  --env-file /etc/relayforge/compose.env \
  ps

sudo find /opt/relayforge -maxdepth 3 -printf '%M %u:%g %p\n' | sort
sudo systemctl list-unit-files \
  relay-cleanup.service relay-cleanup.timer \
  relay-rotate.service relay-rotate.timer relay-worker.service
```

Hardening verification must report zero failures. Compose must show exactly
five healthy containers. The legacy-unit query must show no installed unit
files. Stage-marker checks must prove:

- Web UID 65532 can read Stage 1, but HTTP cannot fetch it directly;
- host `relay` can read Stage 2 but not Stage 3 or `root.txt`; and
- only UID 0 can read Stage 3 and the generated root flag.

Run the local functional suite from the extracted release root:

```bash
./tests/run-vm.sh https://127.0.0.1
```

Then run external negative and full-chain acceptance from the Mac so AWS and
host firewall behavior are included:

```bash
cd "/Users/pengsbook/Documents/Schoolwork (SIT)/Y1T2/ICT2212/DaBox"
python3 tests/negative_paths.py https://18.216.228.46
python3 attacks/full_chain.py https://18.216.228.46
```

The full chain must prove `ROOT_UID=0`,
`ROOT_STAGE=3_UNRESTRICTED_HOST_ROOT`, and an `RF{...}` flag.

## 9. One-time cleanup of inventoried historical artifacts

This is separate from the installer. First print each candidate and confirm it
is the previously inventoried RelayForge scratch/export artifact:

```bash
find "$HOME" -maxdepth 1 -mindepth 1 -printf '%f\n' | sort
sudo find /tmp -maxdepth 1 -mindepth 1 \
  \( -name 'relayforge-release.*' \
     -o -name 'relayforge-deploy.*' \
     -o -name 'relayforge-update.*' \
     -o -name 'relayforge-worker-fix.*' \) \
  -printf '%u:%g %p\n' | sort
```

Only after matching the read-only inventory, remove exact obsolete home paths
one by one. For this EC2 the historical candidates were:

```text
~/apache-site
~/db-export
~/relayforge-db
~/relayforge-export
~/relayforge-export.tar.gz
~/gid  ~/pid  ~/pw_uid  ~/uid
~/supervisor.py.fixed
~/verify-hardening.sh.fixed
```

Keep the current `~/relayforge-upgrade` ZIP/checksum until acceptance is
complete. For `/tmp`, remove only exact printed paths from the inventory;
never delete a `systemd-private-*` directory or use `rm -rf /tmp/relayforge-*`.

Do not use any of these for cleanup:

```bash
sudo apt-get autoremove
sudo docker system prune -a --volumes
sudo docker volume prune
sudo docker compose down --volumes
```

They have a broader ownership boundary than this runbook can prove.

## 10. Failure and rollback rules

- If checksum or manifest verification fails, do not install; repackage and
  upload both files again.
- If the installer reports a foreign running container, identify its owner
  instead of deleting it.
- If TCP 443 remains occupied after RelayForge stops, inspect the reported PID
  and resolve that exact service.
- If a Worker already exists, create a new request after the update before
  judging the new binary.
- Collect `systemctl status`, `journalctl -u`, and Compose logs before changing
  more files.
- `reset-lab.sh --yes` destroys challenge database state and rotates the flag;
  it is not routine cleanup.
- After a participant obtains unrestricted host root, do not rely on the
  installer, reset script, antivirus scan, or manual deletion. Destroy and
  recreate the EC2 from a known-good image.
