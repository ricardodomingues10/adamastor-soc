# Servidor de demonstração para a página Servidores do VulnFlux (laboratório).
# Debian com SSH e sudo, de propósito com a configuração por omissão (palavra-passe no SSH, sem firewall,
# sem auditd): a primeira verificação mostra findings reais de hardening e atualizações pendentes.
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends openssh-server sudo procps iproute2 ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    rm -f /etc/ssh/ssh_host_*
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
