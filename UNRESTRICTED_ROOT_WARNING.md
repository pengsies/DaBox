# Unrestricted-root challenge warning

This branch intentionally ends with arbitrary command execution as **UID 0 on
the Ubuntu host**. The final shell is not container root and is not a
restricted flag-reading helper. A successful participant can modify the host,
Docker, firewall, accounts, SSH configuration, services, and every file visible
to root.

Do not confuse that result with Web UID `65532`, a PostgreSQL database
superuser, container UID 0, or a host service that happens to run as root.
Those are separate identities or trust domains. The dangerous final condition
is **attacker-controlled UID 0 in the host namespace**.

The canonical Supervisor unit also resets `CapabilityBoundingSet=~` and the
host verifier requires its live permitted, effective, and bounding masks to
equal the kernel's complete capability set. A UID-0 process left under the old
five-capability teammate override is not considered the unrestricted-root
variant and causes deployment verification to fail.

Use this build only on a disposable, single-player lab VM. The installer
requires `--acknowledge-unrestricted-root` so this boundary cannot be enabled by
accident.

Before deploying:

- attach no AWS IAM instance profile or other cloud credentials;
- store no personal, institutional, reusable SSH, or application secrets on
  the host;
- place no other workload on the host or its trust network;
- do not reuse administrator credentials or SSH keys elsewhere;
- give only one participant control of an instance at a time; and
- plan to destroy and recreate the VM after compromise.

Players receive only the portal IP and guest Web credentials. Never give them
the EC2 administrator PEM or another sudo/Docker credential: that would grant
an operational shortcut to host root and would not test the RelayForge chain.

On a clean default installation, the review found no known alternate route from
that player starting point to attacker-controlled host UID 0. This is scoped
assurance, not a guarantee. It excludes a deliberately approved endpoint that
is a Docker TCP API, cloud instance-metadata service, or other privileged
service; a kernel/container-runtime escape; a future vulnerability in the
root-running Supervisor; and any other RCE already executing in the active
Worker cgroup. The cgroup check proves where a caller runs, not which exploit
put it there.

The three stage-marker files are source-known teaching breadcrumbs, not secrets
or proof of privilege. Container/process identity, enforced access denials, and
the per-installation root flag provide the evidence. Stage 2 is group-readable
by both host `relay` and host `relay-dispatch`; the Dispatcher container does
not mount the stage directory. The installer always replaces the marker files
with their canonical contents, owners, and modes.

`reset-lab.sh` restores normal challenge state only when the host still behaves
as expected. It cannot undo arbitrary actions taken by unrestricted root.
Installer cleanup cannot do so either. Reimaging from a known-good image is the
only trustworthy reset after the final stage has been solved.

Do not install this branch in place on the shared EC2 instance used for the
bounded flag-disclosure version. Snapshot or replace that instance and deploy
this mode to an isolated machine instead.
