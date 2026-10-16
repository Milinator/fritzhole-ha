# Seit Supervisor 2026.04 wird BUILD_FROM nicht mehr automatisch gesetzt -> Basisimage fest angeben.
ARG BUILD_FROM=ghcr.io/home-assistant/base:3.23
FROM ${BUILD_FROM}

ARG BUILD_VERSION=0.1.0
ARG BUILD_ARCH=amd64

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apk add --no-cache python3

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --only-binary=:all: -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY app /app
WORKDIR /app

# Kein s6-overlay: Docker-Init (config.yaml: init: true) leitet SIGTERM an Python weiter.
ENTRYPOINT []
CMD ["/opt/venv/bin/python3", "-m", "fritzhole"]

LABEL \
    io.hass.name="FritzHole" \
    io.hass.description="DNS-Filter-Dashboard für die FRITZ!Box" \
    io.hass.version="${BUILD_VERSION}" \
    io.hass.type="app" \
    io.hass.arch="${BUILD_ARCH}" \
    org.opencontainers.image.title="Home Assistant App: FritzHole"
