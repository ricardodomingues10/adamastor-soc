# Servidor de demonstração para a página Servidores do VulnFlux (laboratório).
# Debian com SSH e sudo, de propósito com a configuração por omissão (palavra-passe no SSH, sem firewall,
# sem auditd): a primeira verificação mostra findings reais de hardening e atualizações pendentes.
FROM debian:bookworm-slim
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends openssh-server sudo procps iproute2 ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    rm -f /etc/ssh/ssh_host_*
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
