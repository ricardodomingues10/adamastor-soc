# Portal SOC — imagem pequena, sem dependências de sistema além do Python.

FROM python:3.12-slim-trixie

ARG SP_UID=10002

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SP_DATA_DIR=/data \
    SP_CONFIG_FILE=/config/portal.yaml

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends tini ca-certificates; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN set -eux; \
    useradd --system --uid "${SP_UID}" --home-dir /data --shell /usr/sbin/nologin sp; \
    install -d -o sp -g sp -m 0750 /data; \
    install -d -m 0755 /config

USER sp
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["soc-portal"]
