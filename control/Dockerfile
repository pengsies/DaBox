FROM python:3.12.14-slim-bookworm@sha256:9c47360a2a0355e2da18516d0b1c2126ec22c195d2185e97347c9d98398c5bef

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/relayforge
COPY requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt

COPY --chown=0:0 common.py policy.py access.py dispatcher.py healthcheck.py ./
RUN chmod 0555 /opt/relayforge \
 && chmod 0444 /opt/relayforge/*.py /opt/relayforge/requirements.txt

USER 65532:65532
CMD ["python3", "/opt/relayforge/access.py"]
