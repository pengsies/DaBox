the installation-generated `/var/lib/relayforge/flag/root.txt`, owned by root
the acceptance tests still verify the effective UID, namespace/cgroup context,
later-stage denials, and the deployment-generated flag. Because the marker text
# RelayForge Stage Marker Contents

## Stage 1

```text
RELAYFORGE_STAGE=1_WEB_CONTAINER
helooo :D if you see this, it means that you have command execution inside a container but not on the host. your goal is to get root access on the host, remember? if you need some help, try checking out the db adapter
```

## Stage 2

```text
RELAYFORGE_STAGE=2_HOST_RELAY_WORKER
yippee you've finally reached the host (albeit as an unprivileged account)! you should try inspecting the diagnostic interfaces for this active worker if you're stuck
```

## Stage 3

```text
RELAYFORGE_STAGE=3_UNRESTRICTED_HOST_ROOT
well you've technically gotten root on this instance now (i.e. UID 0). if you need more proof just enumerate this instance and find root.txt
```
