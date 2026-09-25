# Unrestricted-root challenge warning

This branch intentionally ends with arbitrary command execution as **UID 0 on
the Ubuntu host**. The final shell is not container root and is not a
restricted flag-reading helper. A successful participant can modify the host,
Docker, firewall, accounts, SSH configuration, services, and every file visible
to root.

Use this build only on a disposable, single-player lab VM. The installer
requires `--acknowledge-unrestricted-root` so this boundary cannot be enabled by
accident.

Before deploying:

- attach no AWS IAM instance profile or other cloud credentials;
- store no personal, institutional, or reusable secrets on the host;
- place no other workload on the host or its trust network;
- do not reuse administrator credentials or SSH keys elsewhere;
- give only one participant control of an instance at a time; and
- plan to destroy and recreate the VM after compromise.

`reset-lab.sh` restores normal challenge state only when the host still behaves
as expected. It cannot undo arbitrary actions taken by unrestricted root.
Reimaging from a known-good image is the only trustworthy reset after the final
stage has been solved.

Do not install this branch in place on the shared EC2 instance used for the
bounded flag-disclosure version. Snapshot or replace that instance and deploy
this mode to an isolated machine instead.
