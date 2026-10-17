# RelayForge Flask Web

This service is the canonical RelayForge Flask portal. It runs as UID/GID
`65532` under Gunicorn on internal port `8080`; nginx is the only
Internet-facing container. Transient host
Workers separately expose authenticated player ports in `25000-25099`.

Required environment:

```text
FLASK_SECRET_KEY
DB_HOST
DB_NAME
DB_USER
DB_PASSWORD
```

Normal HTTP handlers call only `authenticate`, `list_targets`,
`submit_safe_request`, `request_status`, and `cancel_request` in
`relay_web_api`. There is no public raw-request route.

The authenticated `remember_prefs` cookie deliberately contains the
restricted-pickle gadget chain (`RF-WEB-01`/`RF-WEB-02`). A compromised Web
process can invoke the separately granted `submit_raw_request` RPC through
`python3 -m app.raw_rpc`; that moves the Web foothold into signed Worker
provisioning. Stage 2 is reached only after the resulting native Worker is
exploited and the host `relay` shell reads its marker.
`tools/exploit_stage1.py` and `tests/` are repository-only organizer material.
They are copied into neither `/opt/relayforge/app/web` nor the runtime image.

`/opt/relayforge/web/STAGE_1_WEB.txt` is baked into the image as a root-owned,
read-only learning breadcrumb. It is readable after command execution but is
not exposed by a Flask or nginx route. Host Stage 2/3 markers are never mounted
into this container.

There is no database marker. A Web process's database RPC capability does not
prove Worker access, and UID 0 inside a Docker container would not prove host
Stage 3. Host Stage 3 specifically means UID 0 in the Ubuntu host namespace.

The installed Web build context is an explicit allowlist:

```text
.dockerignore
Dockerfile
requirements.txt
prefs.py
STAGE_1_WEB.txt
app/{__init__.py,auth.py,config.py,db.py,raw_rpc.py}
static/style.css
templates/{base.html,connection.html,cookie_policy.html,dashboard.html,login.html}
```

Installer reconciliation removes other entries only from the managed
`/opt/relayforge/app/web` tree. It does not delete repository files, generated
secrets, Docker volumes, user files, or unrelated host data.

Exploit command output is written by the payload to
`/tmp/relayforge-results/<32-lowercase-hex>.txt`. The authenticated result API
accepts only same-UID regular files no larger than 64 KiB and removes each file
after one read. The directory is ephemeral with the container's `/tmp` tmpfs.
