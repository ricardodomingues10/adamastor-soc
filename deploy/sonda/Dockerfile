# Sonda de descoberta: nmap a todas as portas TCP de um host, a pedido do VulnFlux.
# Corre no mesmo sítio da rede que o scanner do Greenbone (vê o que ele vê).
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
RUN apt-get update && apt-get install -y --no-install-recommends nmap python3 && rm -rf /var/lib/apt/lists/*
COPY sonda.py /sonda.py
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"
# Root no contentor (o nmap -sS precisa de raw sockets), mas só com a capacidade NET_RAW (ver compose)
ENTRYPOINT ["python3", "/sonda.py"]
