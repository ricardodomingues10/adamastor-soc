"""Ligar com uma chave: a partir de um URL (e da chave, se houver), descobrir que produto é e montar o serviço.

    1. Impressões digitais: alguns pedidos GET sem credencial a caminhos característicos de cada produto
       (/api/health do Grafana, /alive do Vaultwarden, /realms/master do Keycloak…). Cada sinal que bate soma
       pontos ao modelo do catálogo correspondente.
    2. Com uma chave: os produtos que a aceitam confirmam-se com um pedido autenticado, que também lê a versão.
    3. O melhor candidato vira um serviço: o modelo do catálogo com o URL e a chave do utilizador.

Nunca escreve nada nos serviços: só GET, sem seguir redirecionamentos para outros hosts.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import requests

from socportal.catalog import TEMPLATES_BY_ID
from socportal.config import Settings

# (modelo, caminho, condição, pontos). Condições: status=N · json=caminho.com.pontos · text=regex · header=nome:regex
FINGERPRINTS: list[tuple[str, str, str, int]] = [
    ("vaultwarden", "/alive", "status=200", 2),
    ("vaultwarden", "/api/config", "json=server", 3),
    ("vaultwarden", "/api/config", "text=(?i)vaultwarden|bitwarden", 4),
    ("grafana", "/api/health", "json=database", 6),
    ("keycloak", "/realms/master", "json=realm", 7),
    ("vault", "/v1/sys/health", "json=initialized", 7),
    ("thehive", "/api/status", "text=TheHive", 7),
    ("cortex", "/api/status", "text=Cortex", 7),
    ("misp", "/users/login", "text=(?i)MISP", 6),
    ("defectdojo", "/login", "text=DefectDojo", 7),
    ("defectdojo", "/api/v2/", "header=WWW-Authenticate:Token", 2),
    ("opencti", "/", "text=(?i)OpenCTI", 6),
    ("iris", "/login", "text=(?i)DFIR-IRIS|iris", 4),
    ("shuffle", "/", "text=(?i)Shuffle", 4),
    ("n8n", "/healthz", "json=status", 2),
    ("n8n", "/", "text=(?i)n8n", 4),
    ("glpi", "/", "text=(?i)GLPI", 5),
    ("zabbix", "/", "text=(?i)Zabbix", 6),
    ("uptime-kuma", "/", "text=(?i)Uptime Kuma", 6),
    ("npm", "/api/", "json=version", 3),
    ("npm", "/", "text=(?i)Nginx Proxy Manager", 5),
    ("opensearch", "/", "text=(?i)OpenSearch|You Know, for Search", 6),
    ("opensearch", "/", "header=WWW-Authenticate:(?i)opensearch|security", 2),
    ("graylog", "/api/system/lbstatus", "text=ALIVE", 7),
    ("wazuh", "/", "text=(?i)No authorization token provided|Wazuh", 5),
    ("velociraptor", "/app/index.html", "text=(?i)Velociraptor", 7),
    ("securityonion", "/", "text=(?i)Security Onion", 6),
    ("vulnflux", "/login", "text=VulnFlux", 7),
    ("atalaia-cert", "/entrar", "text=Atalaia", 7),
    ("generic-soc-status", "/api/status", "text=soc-status/1", 3),
    ("generic-soc-status", "/api/status", "text=status_token|VF_STATUS_TOKEN|token inválido", 1),
]

# Com chave: o pedido que confirma o produto e onde vai a chave. "auth" = (cabeçalho, esquema).
KEYED: dict[str, dict[str, Any]] = {
    "defectdojo": {"type": "defectdojo", "url": "/", "auth": ("Authorization", "Token"), "name": "API v2"},
    "misp": {"type": "misp", "url": "/", "auth": ("Authorization", ""), "name": "API"},
    "vulnflux": {"type": "soc-status", "url": "/api/status", "auth": ("Authorization", "Bearer"), "name": "Estado"},
    "atalaia-cert": {"type": "soc-status", "url": "/api/status", "auth": ("Authorization", "Bearer"), "name": "Estado"},
    "generic-soc-status": {
        "type": "soc-status",
        "url": "/api/status",
        "auth": ("Authorization", "Bearer"),
        "name": "Estado",
    },
    "thehive": {
        "type": "http",
        "url": "/api/v1/user/current",
        "auth": ("Authorization", "Bearer"),
        "name": "API",
        "contains": "login",
    },
    "cortex": {
        "type": "http",
        "url": "/api/user/current",
        "auth": ("Authorization", "Bearer"),
        "name": "API",
        "contains": "id",
    },
    "vault": {"type": "http", "url": "/v1/auth/token/lookup-self", "auth": ("X-Vault-Token", ""), "name": "Token"},
    "opensearch": {
        "type": "http",
        "url": "/",
        "auth": ("Authorization", "Basic"),
        "name": "Cluster",
        "version_path": "version.number",
    },
    "n8n": {"type": "http", "url": "/api/v1/workflows?limit=1", "auth": ("X-N8N-API-KEY", ""), "name": "API"},
    "grafana": {"type": "http", "url": "/api/org", "auth": ("Authorization", "Bearer"), "name": "API"},
    "npm": {"type": "http", "url": "/api/", "name": "API", "version_path": "version.major"},
}

# Onde arranjar a chave, por produto (o que o formulário mostra)
KEY_HINTS: dict[str, str] = {
    "vaultwarden": "Não precisa de chave: o estado e a versão são públicos (/alive, /api/config).",
    "grafana": "Opcional: Administration → Service accounts → token com papel Viewer.",
    "keycloak": "Não precisa de chave: o realm é público.",
    "vault": "Opcional: um token com uma policy que só permita auth/token/lookup-self.",
    "thehive": "Organização → Users → utilizador de serviço só de leitura → Create API key.",
    "cortex": "Users → utilizador read → Create API key.",
    "misp": "Administration → List Auth Keys → Add (utilizador com papel read only).",
    "defectdojo": "Menu do utilizador → API v2 Key (um utilizador só de leitura chega).",
    "opensearch": "utilizador:palavra-passe de um utilizador com cluster_monitor.",
    "n8n": "Settings → n8n API → Create an API key.",
    "vulnflux": "O VF_STATUS_TOKEN do VulnFlux.",
    "atalaia-cert": "O CERTWATCH_STATUS_TOKEN do Atalaia Cert.",
    "generic-soc-status": "O token de estado do serviço (contrato soc-status/1).",
    "npm": "Não precisa de chave.",
}


@dataclass
class Candidate:
    template: str
    name: str
    score: int
    evidence: list[str] = field(default_factory=list)
    keyed: bool = False

    @property
    def confidence(self) -> str:
        return "alta" if self.score >= 7 else "média" if self.score >= 4 else "baixa"


@dataclass
class Detection:
    url: str
    reachable: bool
    candidates: list[Candidate]
    error: str = ""
    server: str = ""

    @property
    def best(self) -> Candidate | None:
        return self.candidates[0] if self.candidates else None


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if raw and "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("indica um URL http(s), ex.: https://cofre.exemplo.pt")
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"


def _match(cond: str, resp: requests.Response) -> bool:
    kind, _, arg = cond.partition("=")
    if kind == "status":
        return resp.status_code == int(arg)
    if kind == "text":
        return resp.status_code < 500 and re.search(arg, resp.text[:200_000]) is not None
    if kind == "header":
        name, _, rx = arg.partition(":")
        return re.search(rx, resp.headers.get(name, "")) is not None
    if kind == "json":
        try:
            data = resp.json()
        except ValueError:
            return False
        cur: Any = data
        for part in arg.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return False
            cur = cur[part]
        return True
    return False


def detect(url: str, settings: Settings, session: requests.Session | None = None, *, timeout: float = 5.0) -> Detection:
    base = normalize_url(url)
    sess = session or requests.Session()
    paths = sorted({p for _, p, _, _ in FINGERPRINTS})

    def fetch(path: str) -> tuple[str, requests.Response | None]:
        try:
            return path, sess.get(
                base + path,
                timeout=timeout,
                verify=settings.verify(),
                allow_redirects=False,
                headers={"User-Agent": "soc-portal/detect"},
            )
        except requests.RequestException:
            return path, None

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = dict(pool.map(fetch, paths))
    if all(r is None for r in responses.values()):
        return Detection(
            base, False, [], error="sem resposta: confirma o URL, a porta e se o portal chega lá (rede/proxy)"
        )
    scores: dict[str, Candidate] = {}
    for tid, path, cond, pts in FINGERPRINTS:
        resp = responses.get(path)
        if resp is not None and _match(cond, resp):
            c = scores.setdefault(tid, Candidate(tid, TEMPLATES_BY_ID[tid]["name"], 0))
            c.score += pts
            c.evidence.append(
                f"{path} → {resp.status_code}" + (f" ({cond.split('=', 1)[1][:30]})" if "=" in cond else "")
            )
    # o genérico soc-status só conta se nenhum produto conhecido for detetado
    if any(t != "generic-soc-status" and c.score >= 4 for t, c in scores.items()):
        scores.pop("generic-soc-status", None)
    ranked = sorted(scores.values(), key=lambda c: -c.score)
    server = next((r.headers.get("Server", "") for r in responses.values() if r is not None), "")
    return Detection(base, True, ranked, server=server)


def build_values(template_id: str, url: str, *, key: str = "", user: str = "") -> tuple[dict[str, Any], str]:
    """Valores do formulário de serviço (forms.values_from_template) com o URL e a chave. Devolve (valores, chave)."""
    from socportal.forms import _probe_values, values_from_template

    v = values_from_template(template_id)
    t = TEMPLATES_BY_ID[template_id]
    v["link"] = url
    if t.get("api_url"):
        v["api_url"] = url
    secret = f"{user}:{key}" if user and key else key
    v["_token_slot"] = None
    if secret:
        for i, tp in enumerate(t.get("probes", [])):
            if tp.get("type") in ("defectdojo", "misp", "soc-status") or "auth_scheme" in tp:
                v["_token_slot"] = i
                break
    keyed = KEYED.get(template_id)
    if keyed and secret:
        p: dict[str, Any] = {"type": keyed["type"], "name": keyed["name"], "url": keyed["url"]}
        if "auth" in keyed:
            p["auth_header"], p["auth_scheme"] = keyed["auth"]
        for k in ("contains", "version_path"):
            if k in keyed:
                p[k] = keyed[k]
        keyed_values = _probe_values(p)
        # a verificação autenticada substitui a de vida do mesmo tipo; as outras ficam
        others = [x for x in v["probes"] if x["type"] not in (keyed["type"], "http") or x["url"] != keyed["url"]]
        v["probes"] = [keyed_values, *[x for x in others if x["type"] != keyed["type"]]][:3]
        v["_token_slot"] = 0 if "auth" in keyed else v["_token_slot"]
    return v, secret
