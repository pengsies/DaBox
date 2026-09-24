FROM ubuntu:24.04@sha256:a61567bd31828687156d735ea8eb01ba4e37636e225dd6a48ba94136a70d9d61

ENV container=docker \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential dbus openssl python3 python3-cryptography systemd \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system relayforge-ipc \
 && groupadd --system relay-backend \
 && useradd --system --gid relayforge-ipc --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin relay \
 && useradd --system --gid relayforge-ipc --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin relay-dispatch \
 && useradd --system --gid relay-backend --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin relay-backend \
 && install -d -m 0755 /opt/relayforge/bin /opt/relayforge/runtime /test \
 && install -d -m 0700 /etc/relayforge /etc/relayforge/secrets /var/lib/relayforge/flag \
 && install -d -m 0711 /var/lib/relayforge /var/lib/relayforge/workers

COPY worker/Makefile worker/relay-worker.c /build/
RUN make -C /build clean all \
 && install -o root -g root -m 0755 /build/relay-worker /opt/relayforge/bin/relay-worker \
 && rm -rf /build

COPY host/supervisor.py host/backend.py /opt/relayforge/runtime/
COPY host/relay-supervisor.service host/relay-backend.service /etc/systemd/system/
COPY tests/systemd/sign_job.py tests/systemd/launch_client.py /test/

RUN chmod 0555 /opt/relayforge/runtime/*.py /test/*.py \
 && openssl genpkey -algorithm ED25519 -out /test/job-signing.pem \
 && openssl pkey -in /test/job-signing.pem -pubout -out /etc/relayforge/job-signing.pub \
 && chmod 0400 /test/job-signing.pem \
 && chmod 0444 /etc/relayforge/job-signing.pub \
 && printf 'RF{fedcba98765432100123456789abcdef}\n' > /var/lib/relayforge/flag/root.txt \
 && chown root:root /var/lib/relayforge/flag/root.txt \
 && chmod 0600 /var/lib/relayforge/flag/root.txt \
 && systemctl enable relay-backend.service relay-supervisor.service \
 && systemctl mask systemd-logind.service getty.target console-getty.service

STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
