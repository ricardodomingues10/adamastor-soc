# VulnFlux — orquestrador + interface web + WPScan CLI numa só imagem.
#
# Base trixie (Debian 13): o WPScan 4.x exige Ruby >= 3.3, que o bookworm não tem.

FROM python:3.12-slim-trixie@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

ARG WPSCAN_VERSION=4.2.0
ARG VF_UID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VF_DATA_DIR=/data

# Ruby + WPScan. As ferramentas de compilação só existem durante a instalação das gems;
# libcurl4 fica explicitamente instalada porque o WPScan (ethon/typhoeus) a carrega em runtime.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ruby ruby-dev build-essential libcurl4 libcurl4-openssl-dev zlib1g-dev liblzma-dev \
        openssh-client ca-certificates tini; \
    gem install wpscan -v "${WPSCAN_VERSION}" --no-document; \
    apt-get purge -y --auto-remove build-essential ruby-dev libcurl4-openssl-dev zlib1g-dev liblzma-dev; \
    rm -rf /var/lib/apt/lists/* /root/.gem /root/.cache; \
    wpscan --version --no-banner >/dev/null 2>&1 || wpscan --version >/dev/null

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN set -eux; \
    useradd --system --uid "${VF_UID}" --home-dir /data --shell /usr/sbin/nologin vf; \
    install -d -o vf -g vf -m 0750 /data

USER vf
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["vulnflux"]
