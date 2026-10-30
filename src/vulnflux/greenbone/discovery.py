"""Descoberta de portas antes do Greenbone (perfil "descoberta").

A sonda corre nmap a todas as portas TCP do alvo a partir do mesmo sítio da rede que o
scanner do Greenbone. O VulnFlux transforma as portas abertas numa port list só desse
host: o Greenbone salta a sua própria varredura de portas, que é lenta, e testa tudo o
que está aberto, incluindo serviços em portas fora do normal.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import requests

from vulnflux.config import Settings
from vulnflux.errors import ErrorKind, VFError


@dataclass
class Discovery:
    target: str
    tcp: list[int] = field(default_factory=list)
    hosts_up: int = 0
    seconds: float = 0.0
    nmap: str = ""

    def port_spec(self, udp: str) -> str:
        """Port list no formato do gvmd: T:22,80,…,U:53,161. Sem TCP aberto fica só o UDP."""
        parts = []
        if self.tcp:
            parts.append("T:" + ",".join(str(p) for p in self.tcp))
        udp = ",".join(u.strip() for u in udp.split(",") if u.strip().isdigit())
        if udp:
            parts.append("U:" + udp)
        return ",".join(parts)


def enabled(settings: Settings) -> bool:
    return bool(settings.greenbone_discovery_url.strip())


def discover(settings: Settings, target: str, session: requests.Session | None = None) -> Discovery:
    url = settings.greenbone_discovery_url.rstrip("/") + "/scan"
    token = settings.greenbone_discovery_token.get_secret_value()
    http = session or requests.Session()
    try:
        resp = http.post(
            url,
            json={"target": target},
            headers={"Authorization": f"Bearer {token}"},
            timeout=(10, settings.greenbone_discovery_timeout),
        )
    except requests.RequestException as exc:
        raise VFError(ErrorKind.DEPENDENCY, f"sonda de descoberta inacessível: {exc}") from exc
    if resp.status_code == 401:
        raise VFError(ErrorKind.CONFIG, "sonda de descoberta recusou o token (VF_GREENBONE_DISCOVERY_TOKEN)")
    try:
        body = resp.json()
    except ValueError as exc:
        raise VFError(ErrorKind.DEPENDENCY, f"sonda devolveu HTTP {resp.status_code} sem JSON") from exc
    if resp.status_code != 200:
        raise VFError(ErrorKind.DEPENDENCY, f"sonda: {body.get('error') or resp.status_code}")
    tcp = sorted({int(p) for p in body.get("tcp", []) if 0 < int(p) < 65536})
    return Discovery(
        target=target,
        tcp=tcp,
        hosts_up=int(body.get("hosts_up", 0) or 0),
        seconds=float(body.get("seconds", 0) or 0),
        nmap=str(body.get("nmap", "")),
    )
