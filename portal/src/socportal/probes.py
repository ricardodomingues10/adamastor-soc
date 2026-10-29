"""Verificações dos serviços. Cada uma devolve um ProbeResult e nunca lança exceções.

Tipos:
  http          GET a um URL; ok se o código for o esperado (e o texto aparecer)
  tcp           liga a host:porta (serviços sem HTTP, ex.: gvmd por TCP, PostgreSQL)
  defectdojo    API v2 (com token) + versão lida da própria aplicação
  soc-status    serviço que publica o contrato soc-status/1 (o VulnFlux, e os próximos)
  soc-component componente reportado por outro serviço soc-status (ex.: o Greenbone,
                que não tem interface web e é verificado pelo VulnFlux via GMP)
  misp          /servers/getVersion.json com a chave da API

O contrato soc-status/1 está descrito em docs/soc-status.md.
"""

from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from socportal.config import Settings
from socportal.registry import ProbeDef

OK, WARN, FAIL, OFF, UNKNOWN = "ok", "warn", "fail", "off", "unknown"
STATUSES = (OK, WARN, FAIL, OFF, UNKNOWN)
_RANK = {OK: 0, OFF: 1, UNKNOWN: 2, WARN: 3, FAIL: 4}

SOC_STATUS_SCHEMA = "soc-status/1"
_DD_VERSION = re.compile(r"Version\s+v?(\d+\.\d+\.\d+[\w.+-]*)")


def worst(statuses: list[str]) -> str:
    """Estado agregado. Só 'off' se tudo estiver off (adormecido de propósito)."""
    present = [s for s in statuses if s in _RANK]
    if not present:
        return UNKNOWN
    if all(s == OFF for s in present):
        return OFF
    return max((s for s in present if s != OFF), key=_RANK.__getitem__, default=OK)


def norm_status(value: Any) -> str:
    text = str(value or "").lower()
    if text in STATUSES:
        return text
    return {"ready": OK, "success": OK, "warning": WARN, "failed": FAIL, "error": FAIL, "down": FAIL}.get(text, UNKNOWN)


@dataclass
class ProbeResult:
    status: str
    message: str
    probe: str = ""
    latency_ms: int | None = None
    version: str | None = None
    checks: list[dict[str, Any]] = field(default_factory=list)
    freshness: list[dict[str, Any]] = field(default_factory=list)
    dependencies: dict[str, str] = field(default_factory=dict)
    components: dict[str, dict[str, Any]] = field(default_factory=dict)
    jobs: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "message": self.message,
            "probe": self.probe,
            "latency_ms": self.latency_ms,
            "version": self.version,
            "checks": self.checks,
            "freshness": self.freshness,
            "dependencies": self.dependencies,
            "jobs": self.jobs,
        }


class Prober:
    def __init__(self, settings: Settings, session: requests.Session | None = None) -> None:
        self.settings = settings
        self.session = session or requests.Session()

    # ------------------------------------------------------------------ util
    def _get(self, probe: ProbeDef, url: str, headers: dict[str, str] | None = None) -> tuple[requests.Response, int]:
        verify = self.settings.verify() if probe.verify_tls is None else (probe.verify_tls and self.settings.verify())
        started = time.monotonic()
        resp = self.session.get(
            url,
            headers=headers or {},
            timeout=probe.timeout or self.settings.http_timeout,
            verify=verify,
            allow_redirects=False,
        )
        return resp, round((time.monotonic() - started) * 1000)

    def _slow(self, latency: int | None) -> bool:
        return latency is not None and latency > self.settings.slow_ms

    def run(self, probe: ProbeDef, components: dict[str, dict[str, dict[str, Any]]] | None = None) -> ProbeResult:
        try:
            if probe.type == "http":
                result = self.http(probe)
            elif probe.type == "tcp":
                result = self.tcp(probe)
            elif probe.type == "defectdojo":
                result = self.defectdojo(probe)
            elif probe.type == "soc-status":
                result = self.soc_status(probe)
            elif probe.type == "misp":
                result = self.misp(probe)
            else:
                result = self.soc_component(probe, components or {})
        except requests.exceptions.SSLError:
            result = ProbeResult(FAIL, "erro TLS (certificado? SP_CA_BUNDLE)")
        except requests.Timeout:
            result = ProbeResult(FAIL, f"sem resposta em {probe.timeout or self.settings.http_timeout:.0f}s")
        except requests.ConnectionError:
            result = ProbeResult(FAIL, "inacessível (ligação recusada ou nome não resolvido)")
        except requests.RequestException as exc:
            result = ProbeResult(FAIL, f"erro HTTP: {exc.__class__.__name__}")
        except Exception as exc:  # uma verificação partida não pode parar as outras
            result = ProbeResult(FAIL, f"erro interno na verificação: {exc.__class__.__name__}")
        result.probe = probe.label
        return result

    # ------------------------------------------------------------------ tipos
    def http(self, probe: ProbeDef) -> ProbeResult:
        headers = {}
        token = probe.token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp, latency = self._get(probe, str(probe.url), headers)
        if resp.status_code not in probe.expect_status:
            return ProbeResult(FAIL, f"respondeu {resp.status_code}", latency_ms=latency)
        if probe.contains and probe.contains not in resp.text:
            return ProbeResult(FAIL, f"resposta sem o texto esperado '{probe.contains}'", latency_ms=latency)
        if self._slow(latency):
            return ProbeResult(WARN, f"lento: {latency} ms", latency_ms=latency)
        return ProbeResult(OK, f"{resp.status_code} · {latency} ms", latency_ms=latency)

    def tcp(self, probe: ProbeDef) -> ProbeResult:
        host, port = str(probe.url).rsplit(":", 1)
        started = time.monotonic()
        try:
            with socket.create_connection((host, int(port)), timeout=probe.timeout or self.settings.http_timeout):
                pass
        except OSError as exc:
            return ProbeResult(FAIL, f"{host}:{port} inacessível ({exc.__class__.__name__})")
        latency = round((time.monotonic() - started) * 1000)
        return ProbeResult(OK, f"porta {port} aberta · {latency} ms", latency_ms=latency)

    def defectdojo(self, probe: ProbeDef) -> ProbeResult:
        base = str(probe.url).rstrip("/")
        token = probe.token()
        checks: list[dict[str, Any]] = []
        version = self._dd_version(probe, base, token)

        if not token:
            resp, latency = self._get(probe, f"{base}/login")
            status = OK if resp.status_code == 200 else FAIL
            msg = f"interface {resp.status_code} · {latency} ms (sem token: API não verificada)"
            return ProbeResult(WARN if status == OK else FAIL, msg, latency_ms=latency, version=version)

        resp, latency = self._get(
            probe, f"{base}/api/v2/products/?limit=1", {"Authorization": f"Token {token}", "Accept": "application/json"}
        )
        if resp.status_code in (401, 403):
            return ProbeResult(FAIL, f"token rejeitado ({resp.status_code})", latency_ms=latency, version=version)
        if resp.status_code != 200:
            return ProbeResult(FAIL, f"API respondeu {resp.status_code}", latency_ms=latency, version=version)
        try:
            products = resp.json().get("count")
        except ValueError:
            return ProbeResult(FAIL, "API não devolveu JSON", latency_ms=latency, version=version)
        checks.append({"id": "api", "name": "API v2", "status": OK, "message": f"{latency} ms"})
        status = WARN if self._slow(latency) else OK
        msg = f"API {latency} ms · {products} products"
        if version is None:
            checks.append({"id": "version", "name": "Versão", "status": WARN, "message": "não foi possível ler"})
        return ProbeResult(status, msg, latency_ms=latency, version=version, checks=checks)

    def _dd_version(self, probe: ProbeDef, base: str, token: str | None) -> str | None:
        """A versão aparece no rodapé das páginas; o manifesto de exportação (versões
        recentes) também a devolve. Falhar aqui não é falha do serviço."""
        try:
            resp, _ = self._get(probe, f"{base}/login")
            m = _DD_VERSION.search(resp.text) if resp.status_code == 200 else None
            if m:
                return m.group(1)
            if token:
                resp, _ = self._get(
                    probe,
                    f"{base}/api/v2/export/manifest/",
                    {"Authorization": f"Token {token}", "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    source = data.get("source") if isinstance(data, dict) else None
                    if isinstance(source, dict) and source.get("version"):
                        return str(source["version"])
        except (requests.RequestException, ValueError):
            return None
        return None

    def misp(self, probe: ProbeDef) -> ProbeResult:
        token = probe.token()
        if not token:
            return ProbeResult(FAIL, "chave da API do MISP por definir (token_file/token_env)")
        base = str(probe.url).rstrip("/")
        resp, latency = self._get(
            probe, f"{base}/servers/getVersion.json", {"Authorization": token, "Accept": "application/json"}
        )
        if resp.status_code in (401, 403):
            return ProbeResult(FAIL, f"chave rejeitada ({resp.status_code})", latency_ms=latency)
        if resp.status_code != 200:
            return ProbeResult(FAIL, f"respondeu {resp.status_code}", latency_ms=latency)
        version = str(resp.json().get("version") or "") or None
        status = WARN if self._slow(latency) else OK
        return ProbeResult(status, f"{latency} ms", latency_ms=latency, version=version)

    def soc_status(self, probe: ProbeDef) -> ProbeResult:
        token = probe.token()
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp, latency = self._get(probe, str(probe.url), headers)
        if resp.status_code in (401, 403):
            return ProbeResult(FAIL, f"token rejeitado ({resp.status_code})", latency_ms=latency)
        if resp.status_code == 404:
            try:
                reason = resp.json().get("error")
            except (ValueError, AttributeError):
                reason = None
            if reason:  # o serviço tem o endpoint, mas está desligado (ex.: VF_STATUS_TOKEN vazio)
                return ProbeResult(FAIL, f"estado desligado no serviço: {reason}", latency_ms=latency)
            return ProbeResult(
                FAIL, "404: o serviço não tem /api/status (versão antiga? reconstrói a imagem)", latency_ms=latency
            )
        if resp.status_code != 200:
            return ProbeResult(FAIL, f"respondeu {resp.status_code}", latency_ms=latency)
        try:
            data = resp.json()
        except ValueError:
            return ProbeResult(FAIL, "resposta não é JSON", latency_ms=latency)
        if not isinstance(data, dict) or data.get("schema") != SOC_STATUS_SCHEMA:
            return ProbeResult(FAIL, f"contrato desconhecido (esperado {SOC_STATUS_SCHEMA})", latency_ms=latency)
        result = parse_soc_status(data)
        result.latency_ms = latency
        if result.status == OK and self._slow(latency):
            result.status = WARN
            result.message = f"lento: {latency} ms · {result.message}"
        return result

    def soc_component(self, probe: ProbeDef, components: dict[str, dict[str, dict[str, Any]]]) -> ProbeResult:
        parent = components.get(str(probe.service))
        if parent is None:
            return ProbeResult(UNKNOWN, f"sem dados de {probe.service} (ainda não verificado ou em baixo)")
        comp = parent.get(str(probe.component))
        if comp is None:
            return ProbeResult(UNKNOWN, f"{probe.service} não reporta o componente '{probe.component}'")
        return ProbeResult(
            norm_status(comp.get("status")),
            str(comp.get("message") or ""),
            version=str(comp["version"]) if comp.get("version") else None,
            checks=_list_of_dicts(comp.get("checks")),
            freshness=_list_of_dicts(comp.get("freshness")),
        )


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return [dict(x) for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def parse_soc_status(data: dict[str, Any]) -> ProbeResult:
    checks = _list_of_dicts(data.get("checks"))
    for c in checks:
        c["status"] = norm_status(c.get("status"))
    freshness = _list_of_dicts(data.get("freshness"))
    components = {str(k): dict(v) for k, v in (data.get("components") or {}).items() if isinstance(v, dict)}
    deps = {str(k): norm_status(v) for k, v in (data.get("dependencies") or {}).items()}
    jobs = _list_of_dicts(data.get("jobs"))
    for j in jobs:
        if j.get("last_status"):
            j["last_status"] = norm_status(j["last_status"])
    return ProbeResult(
        norm_status(data.get("status")),
        str(data.get("message") or ""),
        version=str(data["version"]) if data.get("version") else None,
        checks=checks,
        freshness=freshness,
        dependencies=deps,
        components=components,
        jobs=jobs,
    )
