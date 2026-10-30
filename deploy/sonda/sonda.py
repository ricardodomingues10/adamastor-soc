"""Sonda de descoberta do Adamastor SOC.

POST /scan {"target": "host ou IP"} com "Authorization: Bearer <SONDA_TOKEN>"
→ {"target", "tcp": [portas abertas], "seconds", "nmap"}
GET /healthz → ok

Um scan de cada vez. Só aceita um host (nome ou IPv4/IPv6), nunca opções do nmap.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$"
)
LOCK = threading.Lock()
MIN_RATE = os.environ.get("SONDA_MIN_RATE", "1000")
HOST_TIMEOUT = os.environ.get("SONDA_HOST_TIMEOUT", "20m")


def token() -> str:
    path = os.environ.get("SONDA_TOKEN_FILE", "")
    if path and os.path.exists(path):
        return open(path).read().strip()
    return os.environ.get("SONDA_TOKEN", "")


def valid_target(t: str) -> bool:
    if not t or t.startswith("-"):
        return False
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return bool(NAME.match(t))


def nmap_version() -> str:
    out = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=10).stdout
    return out.split("\n", 1)[0].strip()


def scan(target: str) -> dict:
    cmd = [
        "nmap",
        "-n",
        "-Pn",
        "-sS",
        "-p-",
        "--open",
        "--min-rate",
        MIN_RATE,
        "--max-retries",
        "2",
        "--host-timeout",
        HOST_TIMEOUT,
        "-oX",
        "-",
    ]
    if ":" in target:
        cmd.append("-6")
    cmd += ["--", target]
    started = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout)[-500:])
    root = ET.fromstring(proc.stdout)
    ports = sorted(
        int(p.get("portid"))
        for p in root.iter("port")
        if p.get("protocol") == "tcp" and (p.find("state") is not None and p.find("state").get("state") == "open")
    )
    hosts_up = sum(
        1 for h in root.iter("host") if (h.find("status") is not None and h.find("status").get("state") == "up")
    )
    return {
        "target": target,
        "tcp": ports,
        "hosts_up": hosts_up,
        "seconds": round(time.monotonic() - started, 1),
        "nmap": nmap_version(),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "sonda"
    sys_version = ""

    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "não encontrado"})

    def do_POST(self) -> None:  # noqa: N802
        expected = token()
        got = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not expected or not hmac.compare_digest(got.encode(), expected.encode()):
            self._send(401, {"error": "token inválido"})
            return
        if self.path != "/scan":
            self._send(404, {"error": "não encontrado"})
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 4096)
            target = str(json.loads(self.rfile.read(length) or b"{}").get("target", "")).strip()
        except (ValueError, AttributeError):
            self._send(400, {"error": "JSON inválido"})
            return
        if not valid_target(target):
            self._send(400, {"error": "alvo inválido: um nome ou IP, sem opções"})
            return
        if not LOCK.acquire(timeout=1800):
            self._send(503, {"error": "ocupada"})
            return
        try:
            self._send(200, scan(target))
        except Exception as exc:  # noqa: BLE001
            self._send(502, {"error": f"nmap falhou: {exc}"})
        finally:
            LOCK.release()

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
