# RelayForge access-stage markers

RelayForge installs three plain-text learning breadcrumbs so a player can tell
which privilege boundary they have crossed. They describe the current identity,
what that identity cannot do, and the next intended boundary.

| Stage | Runtime path | Expected reader | Meaning |
|---|---|---|---|
| 1 | `/opt/relayforge/web/STAGE_1_WEB.txt` | Web UID 65532 | Command execution is inside the Flask container only. |
| 2 | `/var/lib/relayforge/stages/STAGE_2_WORKER.txt` | Host `relay` Worker; technically also host `relay-dispatch` by group membership | The native Worker exploit produced an unprivileged host shell. |
| 3 | `/var/lib/relayforge/stages/STAGE_3_ROOT.txt` | Host UID 0 only | The Supervisor race produced unrestricted host root. |

Stage 1 is baked into only the Web image as `root:root` mode `0444`. The host
stage directory is not mounted into any container. Stage 2 is installed as
`root:relayforge-ipc` mode `0440`, so the transient Worker can read it while its
systemd sandbox keeps it read-only. The host `relay-dispatch` account is also a
member of `relayforge-ipc`, so a process actually running under that host
identity can read Stage 2 as well. The Dispatcher container has no host-stage
mount, and the marker is neither a secret nor an authorization boundary. Stage
3 is installed as `root:root` mode `0400`; the `relay` shell must fail to read
it.

The canonical installer rewrites all three markers from the release and
restores their expected ownership and modes on every installation. This makes
the exercise repeatable and repairs accidental marker drift. It is not an
incident-recovery mechanism after a participant has controlled host root.

These files are committed to the organizer repository and therefore are not
secret or suitable as score-submission flags. The actual scoring secret remains
the installation-generated `/var/lib/relayforge/flag/root.txt`, owned by root
with mode `0600`. Reading a marker is useful evidence of location and identity;
the acceptance tests still verify the effective UID, namespace/cgroup context,
later-stage denials, and the deployment-generated flag. Because the marker text
is committed, a player can quote it without ever reaching that stage; marker
contents alone are never proof of access.

The legitimate browser tunnel is not a privilege stage. Reaching the sample
endpoint proves that the product feature works, but it does not provide command
execution in the Web container or on the host.

## UID-0 shortcut assessment

UID 0 already exists in infrastructure by design: the host Docker daemon and
RelayForge Supervisor are root services, and an image entrypoint/master process
may use container UID 0 before or while dropping to its service user. That is
different from attacker-controlled UID-0 execution. Container UID 0 is also a
different privilege domain from Ubuntu host UID 0 unless a separate container
escape or dangerous host-control mount exists.

A PostgreSQL `postgres` database superuser is another separate trust domain: it
controls the database cluster, not the Ubuntu host. Likewise, a root-owned host
service is not attacker-controlled host root merely because its process UID is
0. Stage 3 means that participant-supplied commands are executing as UID 0 in
the host namespace.

The reviewed application has no known alternate host-UID-0 route from the
documented player starting point (public HTTPS plus the `guest` Web account) on
a fresh deployment using the bundled `127.0.0.1:19001` endpoint. The boundaries
that support that conclusion are tested, not merely documented: containers are
unprivileged and receive no Docker socket; database roles and Supervisor RPC
operations are separated; launch payloads are signed; diagnose requires kernel
UID `relay` in the exact active Worker cgroup; and the Worker has no capabilities
or direct read access to Stage 3 or `root.txt`.

Conversely, Stage 3 is deliberately not a capability-reduced form of UID 0.
The canonical Supervisor resets its bounding set to the full kernel capability
mask, and host verification compares the live process masks against the
kernel's advertised last capability.

That is not a mathematical guarantee. The following would bypass or change the
model and must be treated separately:

- Giving a participant the EC2 administrator PEM or another account with
  `sudo`/Docker access. Players receive the portal address and guest Web
  credentials, never that PEM.
- Configuring the approved tunnel endpoint as a privileged unauthenticated
  service, Docker TCP API, cloud instance-metadata endpoint, or another
  sensitive target.
- A kernel, Docker/runtime, container escape, nginx, PostgreSQL, or
  local-service vulnerability outside the intended application chain.
- A future bug in the deliberately unrestricted root Supervisor.
- Any future alternate code-execution primitive inside the active Worker's
  cgroup. Diagnose proves the caller's kernel identity and cgroup, not that the
  caller used this release's callback overwrite specifically.

For those reasons the player receives only the portal IP and guest credentials,
the endpoint stays pinned to the harmless bundled fixture, the host stays
patched and contains no reusable SSH keys, personal secrets, cloud credentials,
or instance role. The VM is disposable and single-player. Installer cleanup or
`reset-lab.sh` can restore canonical challenge files on an uncompromised host;
after Stage 3, destroy and recreate the VM from a known-good image instead.
