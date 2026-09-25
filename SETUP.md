# RelayForge Windows-to-Ubuntu setup and acceptance guide

> **Unrestricted-root variant:** a successful player obtains real UID 0 on the
> Ubuntu host. Use a disposable, single-player VM with no IAM role, reusable
> credentials, sensitive data, or other workloads. Do not install this branch
> on the shared Group 30 EC2. Read `UNRESTRICTED_ROOT_WARNING.md` first.

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

## 1. Required files

Distribute these two files together:

```text
RelayForge-Responsibilities-Flask-v1.zip
RelayForge-Responsibilities-Flask-v1.zip.sha256
```

Do not distribute `responsibilities/diff/` or the raw teammate prototypes as
deployment inputs. The release archive contains only the integrated
`responsibilities/shared/` tree.

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

The installer also copies the version-controlled
`config/60-relayforge-sysctl.conf` to
`/etc/sysctl.d/60-relayforge.conf`. Make lasting sysctl changes in the project
file as well as on the host, or a later installation will replace them.

RelayForge expects these runtime ownership boundaries:

```text
/etc/relayforge/job-signing.pub       root:root            0444
/var/lib/relayforge/workers           root:root            0711
/var/lib/relayforge/flag/root.txt     root:root            0600
/run/relayforge/supervisor.sock       root:relayforge-ipc  0660
```

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
values. Cancel active connections through the portal or wait for their bounded
lifetime to expire, confirm no Worker is running, and then rerun the installer
from a newly verified and newly extracted release:

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

Both Worker markers must be present. A Worker that was already running when the
binary was replaced retains its old loaded executable; create a new portal
request after the update.

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
curl --fail http://127.0.0.1:19001/health
curl --fail --insecure https://127.0.0.1/healthz
```

Acceptance requires zero deployment-verification failures, five healthy containers, all
listed host services active, and both health requests succeeding.

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

## 13. Optional housekeeping

No periodic cleanup is required. Supervisor normally reaps expired Worker
state, Compose starts with `--remove-orphans`, and old images are harmless while
disk space remains adequate.

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

Old, positively identified `/tmp/relayforge-*` extraction/build directories may
be removed after the verified ZIP and checksum are retained. Do not manually
remove `/opt/relayforge`, `/etc/relayforge`, `/var/lib/relayforge`, or any
RelayForge Docker volume. Do not use `docker system prune -a --volumes`,
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
