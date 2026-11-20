"""Vulnerabilidades por componente WordPress, com cache partilhada entre sites.

A API do WPScan responde "todas as vulnerabilidades deste plugin" num só pedido. Um scan por site
gasta um pedido por componente; aqui cada plugin, tema ou versão do WordPress é consultado uma vez
e a resposta serve todos os sites que o usam. Com sites que partilham a maior parte dos plugins,
50 sites com 30 plugins em comum custam cerca de 30 pedidos em vez de mais de 1 000.

A enumeração dos sites (que plugins e versões têm) é feita pelo WPScan sem chave, sem gastar quota.
A comparação de versões é feita aqui, com as mesmas regras do WPScan (introduced_in, fixed_in).
"""

from __future__ import annotations

import json
import logging
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import requests
from packaging.version import InvalidVersion, Version

from vulnflux.collectors.wpscan_tokens import TokenPool
from vulnflux.config import Settings
from vulnflux.errors import ErrorKind, VFError
from vulnflux.models import utcnow

log = logging.getLogger(__name__)
# O lote WPScan e o vigilante usam instâncias diferentes da cache: a escrita relê o ficheiro e junta.
_FILE_LOCK = threading.Lock()

KINDS = ("wordpress", "plugin", "theme")
_ENDPOINT = {"wordpress": "wordpresses", "plugin": "plugins", "theme": "themes"}
_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,120}$", re.IGNORECASE)


def api_key(kind: str, slug: str) -> str:
    return f"{kind}:{slug.lower()}"


def fetch_component(settings: Settings, kind: str, slug: str, token: str, timeout: int = 20) -> dict[str, Any]:
    """Um pedido à API: todas as vulnerabilidades conhecidas do componente (e a versão mais recente).

    Para o WordPress, `slug` é a versão (6.4.1). Um componente que a API não conhece (404, ex.: um
    plugin feito à medida) devolve uma entrada vazia com not_found=True.
    """
    if kind not in KINDS or not _SLUG.match(slug):
        raise VFError(ErrorKind.DATA, f"componente inválido: {kind} {slug!r}")
    path = slug.replace(".", "") if kind == "wordpress" else slug
    url = f"{settings.wpscan_api_url.rstrip('/')}/{_ENDPOINT[kind]}/{path}"
    try:
        resp = requests.get(url, headers={"Authorization": f"Token token={token}"}, timeout=timeout)
    except requests.RequestException as exc:
        raise VFError(ErrorKind.DEPENDENCY, f"API do WPScan inacessível: {exc.__class__.__name__}") from exc
    if resp.status_code == 404:
        return {"not_found": True, "vulnerabilities": []}
    if resp.status_code in (401, 403):
        raise VFError(ErrorKind.CONFIG, "chave WPScan inválida")
    if resp.status_code == 429:
        raise VFError(ErrorKind.QUOTA, "chave WPScan sem quota (HTTP 429)")
    if resp.status_code != 200:
        raise VFError(ErrorKind.DEPENDENCY, f"API do WPScan respondeu {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise VFError(ErrorKind.DEPENDENCY, "API do WPScan devolveu uma resposta inválida") from exc
    if not isinstance(data, dict):
        raise VFError(ErrorKind.DEPENDENCY, "API do WPScan devolveu uma resposta inesperada")
    # A resposta vem indexada pelo slug (ou pela versão, no WordPress); aceita qualquer chave única.
    node = data.get(slug) or data.get(slug.lower()) or (next(iter(data.values())) if len(data) == 1 else None)
    if not isinstance(node, dict):
        return {"not_found": True, "vulnerabilities": []}
    vulns = node.get("vulnerabilities") or []
    return {
        "not_found": False,
        "latest_version": node.get("latest_version"),
        "last_updated": node.get("last_updated"),
        "status": node.get("status"),  # WordPress: latest | outdated | insecure
        "vulnerabilities": [v for v in vulns if isinstance(v, dict)],
    }


# ---------------------------------------------------------------------------- versões


def _loose(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:6]) or (0,)


def version_lt(a: str, b: str) -> bool:
    try:
        return Version(a) < Version(b)
    except InvalidVersion:
        return _loose(a) < _loose(b)


def affects(version: str | None, vuln: dict[str, Any]) -> bool:
    """A vulnerabilidade afeta esta versão? Sem versão conhecida, conta (como no WPScan)."""
    if not version:
        return True
    fixed, introduced = vuln.get("fixed_in"), vuln.get("introduced_in")
    if introduced and version_lt(str(version), str(introduced)):
        return False
    return not (fixed and not version_lt(str(version), str(fixed)))


# ---------------------------------------------------------------------------- cache


@dataclass
class Lookup:
    """Resultado de pedir as vulnerabilidades de um componente."""

    entry: dict[str, Any] | None
    source: str  # cache | api | antiga | nenhuma
    age_hours: float | None = None


@dataclass
class Budget:
    """Pedidos à API feitos (e recusados por falta de quota) numa execução."""

    used: int = 0
    denied: int = 0
    keys: list[str] = field(default_factory=list)


class VulnCache:
    """data_dir/wp_vulndb.json: {chave: {fetched_at, latest_version, vulnerabilities, ...}}."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.path = Path(settings.data_dir) / "wp_vulndb.json"
        self._lock = threading.RLock()
        self.entries: dict[str, dict[str, Any]] = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text("utf-8"))
            return data.get("entries", {}) if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": 1, "entries": self.entries}, ensure_ascii=False), "utf-8")
        tmp.replace(self.path)

    def get(self, kind: str, slug: str) -> dict[str, Any] | None:
        with self._lock:
            return self.entries.get(api_key(kind, slug))

    def age_hours(self, entry: dict[str, Any] | None) -> float | None:
        if not entry or not entry.get("fetched_at"):
            return None
        return (utcnow() - datetime.fromisoformat(entry["fetched_at"])).total_seconds() / 3600

    def fresh(self, entry: dict[str, Any] | None) -> bool:
        age = self.age_hours(entry)
        return age is not None and age < self.settings.wpscan_cache_hours

    def put(self, kind: str, slug: str, data: dict[str, Any]) -> dict[str, Any]:
        with self._lock, _FILE_LOCK:
            entry = {**data, "kind": kind, "slug": slug, "fetched_at": utcnow().isoformat()}
            current = self._load()
            current[api_key(kind, slug)] = entry
            self.entries = current
            self._save()
            return entry

    def lookup(self, kind: str, slug: str, pool: TokenPool | None, budget: Budget) -> Lookup:
        """Da cache se estiver fresca; senão um pedido à API (rodando as chaves); senão a antiga."""
        entry = self.get(kind, slug)
        if self.fresh(entry):
            return Lookup(entry, "cache", self.age_hours(entry))
        tried: set[str] = set()
        while pool is not None:
            choice = pool.choose(exclude=tried, allow_low=True)
            if choice is None:
                break
            fp, token = choice
            try:
                data = fetch_component(self.settings, kind, slug, token)
            except VFError as exc:
                if exc.kind is ErrorKind.QUOTA:
                    pool.mark_exhausted(fp, exc.message)
                    tried.add(fp)
                    continue
                if exc.kind is ErrorKind.CONFIG:
                    tried.add(fp)
                    continue
                log.warning("vulnerabilidades de %s %s não obtidas: %s", kind, slug, exc.message)
                break
            pool.record(fp, None)
            budget.used += 1
            label = pool.label_of(fp)
            if label not in budget.keys:
                budget.keys.append(label)
            return Lookup(self.put(kind, slug, data), "api", 0.0)
        budget.denied += 1
        if entry is not None:
            return Lookup(entry, "antiga", self.age_hours(entry))
        return Lookup(None, "nenhuma")

    def stale(self, older_than: timedelta | None = None) -> list[dict[str, Any]]:
        limit = (older_than or timedelta(hours=self.settings.wpscan_cache_hours)).total_seconds() / 3600
        with self._lock:
            return [e for e in self.entries.values() if (self.age_hours(e) or 1e9) >= limit]


def prefetch(cache: VulnCache, pool: TokenPool | None, wanted: dict[tuple[str, str], int]) -> Budget:
    """Antes do lote: refresca os componentes já conhecidos por ordem justa.

    Sem isto, os componentes dos primeiros sites do lote gastavam a quota todos os dias e os dos
    últimos nunca chegavam a ter dados. Ordem: nunca obtidos, depois os mais antigos; em empate, os
    usados por mais sites.
    """
    budget = Budget()
    if pool is None:
        return budget
    todo = []
    for (kind, slug), sites in wanted.items():
        entry = cache.get(kind, slug)
        if cache.fresh(entry):
            continue
        age = cache.age_hours(entry)
        todo.append((0 if age is None else 1, -(age or 0), -sites, kind, slug))
    for *_rank, kind, slug in sorted(todo):
        if cache.lookup(kind, slug, pool, budget).source != "api":
            break  # sem quota em nenhuma chave
    return budget


# ---------------------------------------------------------------------------- enriquecimento


def components(raw: dict[str, Any]) -> list[tuple[str, str, str | None, dict[str, Any]]]:
    """(tipo, slug, versão instalada, nó do JSON) de cada componente encontrado pelo WPScan."""
    out: list[tuple[str, str, str | None, dict[str, Any]]] = []
    version = raw.get("version")
    if isinstance(version, dict) and version.get("number"):
        out.append(("wordpress", str(version["number"]), str(version["number"]), version))
    themes: dict[str, Any] = {}
    main_theme = raw.get("main_theme")
    if isinstance(main_theme, dict) and main_theme.get("slug"):
        themes[main_theme["slug"]] = main_theme
    for slug, node in (raw.get("themes") or {}).items():
        themes.setdefault(slug, node)
    for kind, nodes in (("theme", themes), ("plugin", raw.get("plugins") or {})):
        for slug, node in nodes.items():
            if not isinstance(node, dict) or not _SLUG.match(str(slug)):
                continue
            ver = (node.get("version") or {}).get("number") if isinstance(node.get("version"), dict) else None
            out.append((kind, str(slug), str(ver) if ver else None, node))
    return out


@dataclass
class Enrichment:
    checked: int = 0
    from_api: int = 0
    stale: list[str] = field(default_factory=list)  # componentes com dados antigos
    unchecked: list[str] = field(default_factory=list)  # sem dados nenhuns
    vulnerable: int = 0
    budget: Budget = field(default_factory=Budget)


def enrich(raw: dict[str, Any], cache: VulnCache, pool: TokenPool | None) -> Enrichment:
    """Junta ao JSON do WPScan (enumerado sem chave) as vulnerabilidades que afetam cada versão.

    O resultado tem o mesmo formato de um scan feito com chave, por isso o conversor para o
    DefectDojo é o mesmo.
    """
    result = Enrichment()
    for kind, slug, version, node in components(raw):
        look = cache.lookup(kind, slug, pool, result.budget)
        label = f"{kind} {slug}"
        if look.entry is None:
            result.unchecked.append(label)
            node["vulnerabilities"] = []
            continue
        result.checked += 1
        if look.source == "api":
            result.from_api += 1
        elif look.source == "antiga":
            result.stale.append(f"{label} ({look.age_hours:.0f} h)")
        found = [v for v in look.entry.get("vulnerabilities") or [] if affects(version, v)]
        node["vulnerabilities"] = found
        if kind != "wordpress" and look.entry.get("latest_version"):
            node["latest_version"] = look.entry["latest_version"]
        result.vulnerable += len(found)
    raw["vuln_api"] = {
        "plan": "partilhado",
        "requests_done_during_scan": result.budget.used,
        "components_checked": result.checked,
        "components_unchecked": len(result.unchecked),
    }
    return result
