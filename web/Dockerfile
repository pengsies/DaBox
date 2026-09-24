FROM python:3.12.14-slim-bookworm@sha256:9c47360a2a0355e2da18516d0b1c2126ec22c195d2185e97347c9d98398c5bef

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/relayforge/web

COPY requirements.txt ./
RUN python3 -m pip install --no-cache-dir --requirement requirements.txt

COPY --chown=0:0 app/ ./app/
COPY --chown=0:0 templates/ ./templates/
COPY --chown=0:0 static/ ./static/
COPY --chown=0:0 prefs.py ./prefs.py

RUN find /opt/relayforge/web -type d -exec chmod 0555 {} + \
    && find /opt/relayforge/web -type f -exec chmod 0444 {} +

USER 65532:65532
EXPOSE 8080

CMD ["gunicorn", "--bind=0.0.0.0:8080", "--workers=2", "--threads=2", "--timeout=15", "--graceful-timeout=10", "--keep-alive=2", "--worker-tmp-dir=/tmp", "--access-logfile=-", "--error-logfile=-", "app:create_app()"]

