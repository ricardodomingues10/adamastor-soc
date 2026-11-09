# Sonda de descoberta: nmap a todas as portas TCP de um host, a pedido do VulnFlux.
# Corre no mesmo sítio da rede que o scanner do Greenbone (vê o que ele vê).
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update && apt-get install -y --no-install-recommends nmap python3 && rm -rf /var/lib/apt/lists/*
COPY sonda.py /sonda.py
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"
# Root no contentor (o nmap -sS precisa de raw sockets), mas só com a capacidade NET_RAW (ver compose)
ENTRYPOINT ["python3", "/sonda.py"]
