# RelayForge Flask Web

This service integrates the teammate Flask portal design with the canonical
RelayForge database API. It runs as UID/GID `65532` under Gunicorn on internal
port `8080`; nginx is the only Internet-facing service.

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

The authenticated `remember_prefs` cookie deliberately retains the teammate's
restricted-pickle gadget chain (`RF-WEB-01`/`RF-WEB-02`). A compromised Web
process can invoke the separately granted `submit_raw_request` RPC through
`python3 -m app.raw_rpc`; that is the intended Stage 1 to Stage 2 boundary.
`tools/exploit_stage1.py` is the authorized lab verifier and is not copied into
the runtime image.

Exploit command output is written by the payload to
`/tmp/relayforge-results/<32-lowercase-hex>.txt`. The authenticated result API
accepts only same-UID regular files no larger than 64 KiB and removes each file
after one read. The directory is ephemeral with the container's `/tmp` tmpfs.

