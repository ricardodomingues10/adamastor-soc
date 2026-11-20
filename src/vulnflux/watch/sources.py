"""Fontes do vigilante: o que saiu de novo (versões e vulnerabilidades) desde a última verificação.

Cada fonte devolve observações; o vigilante compara-as com o estado anterior e só alerta o que é novo.

  wordpress.org  versão atual do núcleo e de cada plugin/tema instalado (sem chave, sem limite apertado)
  WPScan         vulnerabilidades por componente, a partir da cache partilhada (não gasta pedidos)
                 e, com quota de sobra, refrescando os componentes mais usados
  Wordfence      feed de vulnerabilidades (chave gratuita), cruzado com os componentes instalados
  GitHub         última release das ferramentas do SOC (n8n, Greenbone, DefectDojo...)
  RSS/Atom       qualquer feed de avisos (CERT, fornecedores)
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

import requests
from lxml import etree

from vulnflux.config import Settings
from vulnflux.wordpress.vulndb import version_lt

log = logging.getLogger(__name__)

UA = "VulnFlux-watch/1 (+https://github.com/ricardodomingues10/adamastor-soc)"
WPORG = "https://api.wordpress.org"


@dataclass
class Release:
    kind: str  # wordpress | plugin | theme | tool
    slug: str
    version: str
    source: str
    url: str = ""
    published: str = ""


@dataclass
class Vulnerability:
    kind: str
    slug: str
    vuln_id: str
    title: str
    source: str
    fixed_in: str | None = None
    introduced_in: str | None = None
    # Wordfence: intervalos [{from, from_inclusive, to, to_inclusive}] em vez de introduced/fixed
    ranges: list[dict[str, Any]] = field(default_factory=list)
    score: float | None = None
    cves: list[str] = field(default_factory=list)
    url: str = ""


@dataclass
class Advisory:
    feed: str
    item_id: str
    title: str
    url: str = ""
    published: str = ""


@dataclass
class Observations:
    releases: list[Release] = field(default_factory=list)
    vulns: list[Vulnerability] = field(default_factory=list)
    advisories: list[Advisory] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    requests: int = 0
    # "fonte:tipo:slug" de cada componente consultado, com ou sem vulnerabilidades (estado inicial)
    observed: set[str] = field(default_factory=set)


def _get(
    url: str, *, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None, timeout: int = 20
) -> requests.Response:
    return requests.get(url, params=params, headers={"User-Agent": UA, **(headers or {})}, timeout=timeout)


# ---------------------------------------------------------------------------- wordpress.org


def wporg_core(obs: Observations) -> None:
    try:
        resp = _get(f"{WPORG}/core/version-check/1.7/")
        obs.requests += 1
        offers = resp.json().get("offers") or []
        version = next(
            (o.get("current") or o.get("version") for o in offers if o.get("response") in ("upgrade", "latest")), None
        ) or (offers[0].get("current") if offers else None)
    except (requests.RequestException, ValueError, AttributeError) as exc:
        obs.errors.append(f"wordpress.org (núcleo): {exc.__class__.__name__}")
        return
    if version:
        obs.releases.append(
            Release("wordpress", "core", str(version), "wordpress.org", "https://wordpress.org/news/category/releases/")
        )


def wporg_component(obs: Observations, kind: str, slug: str) -> None:
    """Versão atual de um plugin ou tema do diretório oficial. Os premium não estão lá (ignorados)."""
    action = "plugin_information" if kind == "plugin" else "theme_information"
    section = "plugins" if kind == "plugin" else "themes"
    params = {
        "action": action,
        "request[slug]": slug,
        "request[fields][sections]": "0",
        "request[fields][versions]": "0",
        "request[fields][reviews]": "0",
    }
    try:
        resp = _get(f"{WPORG}/{section}/info/1.2/", params=params)
        obs.requests += 1
        if resp.status_code == 404:
            return
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        obs.errors.append(f"wordpress.org ({kind} {slug}): {exc.__class__.__name__}")
        return
    if not isinstance(data, dict) or data.get("error") or not data.get("version"):
        return  # não existe no diretório (plugin premium ou feito à medida)
    obs.releases.append(
        Release(
            kind,
            slug,
            str(data["version"]),
            "wordpress.org",
            f"https://wordpress.org/{section}/{slug}/",
            str(data.get("last_updated") or ""),
        )
    )


# ---------------------------------------------------------------------------- WPScan (cache)


def vuln_id(source: str, v: dict[str, Any]) -> str:
    raw = v.get("id") or v.get("uuid") or f"{v.get('title')}|{v.get('fixed_in')}|{v.get('introduced_in')}"
    return (
        f"{source}:{raw}"
        if v.get("id") or v.get("uuid")
        else f"{source}:" + hashlib.sha1(str(raw).encode(), usedforsecurity=False).hexdigest()[:16]
    )


def _score(v: dict[str, Any]) -> float | None:
    cvss = v.get("cvss")
    if isinstance(cvss, dict):
        try:
            return float(cvss.get("score"))
        except (TypeError, ValueError):
            return None
    return None


def wpscan_from_cache(obs: Observations, entries: list[dict[str, Any]]) -> None:
    for e in entries:
        kind, slug = e.get("kind"), e.get("slug")
        if not kind or not slug:
            continue
        obs.observed.add(f"WPScan:{kind}:{slug}")
        for v in e.get("vulnerabilities") or []:
            refs = v.get("references") or {}
            cves = [c if str(c).upper().startswith("CVE-") else f"CVE-{c}" for c in refs.get("cve") or []]
            wpvulndb = (refs.get("wpvulndb") or [None])[0]
            obs.vulns.append(
                Vulnerability(
                    kind,
                    slug,
                    vuln_id("wpscan", v),
                    str(v.get("title") or "?"),
                    "WPScan",
                    fixed_in=v.get("fixed_in"),
                    introduced_in=v.get("introduced_in"),
                    score=_score(v),
                    cves=cves,
                    url=f"https://wpscan.com/vulnerability/{wpvulndb}" if wpvulndb else "",
                )
            )
        if kind != "wordpress" and e.get("latest_version"):
            obs.releases.append(Release(kind, slug, str(e["latest_version"]), "WPScan"))


# ---------------------------------------------------------------------------- Wordfence


def wordfence(obs: Observations, settings: Settings, installed: set[tuple[str, str]]) -> None:
    """Feed de vulnerabilidades da Wordfence Intelligence, só para os componentes instalados."""
    token = settings.watch_wordfence_token.get_secret_value()
    if not token:
        return
    try:
        resp = _get(settings.watch_wordfence_url, headers={"Authorization": f"Bearer {token}"}, timeout=120)
        obs.requests += 1
        if resp.status_code in (401, 403):
            obs.errors.append("Wordfence: chave inválida")
            return
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        obs.errors.append(f"Wordfence: {exc.__class__.__name__}")
        return
    items = data.values() if isinstance(data, dict) else data if isinstance(data, list) else []
    obs.observed.update(f"Wordfence:{kind}:{slug}" for kind, slug in installed)
    for item in items:
        if not isinstance(item, dict):
            continue
        for sw in item.get("software") or []:
            kind = {"core": "wordpress"}.get(sw.get("type"), sw.get("type"))
            slug = sw.get("slug") or ""
            key = (kind, "core" if kind == "wordpress" else slug)
            if key not in installed:
                continue
            ranges = []
            for r in (sw.get("affected_versions") or {}).values():
                if isinstance(r, dict):
                    ranges.append(
                        {
                            "from": r.get("from_version"),
                            "from_inclusive": r.get("from_inclusive", True),
                            "to": r.get("to_version"),
                            "to_inclusive": r.get("to_inclusive", True),
                        }
                    )
            cvss = item.get("cvss") or {}
            try:
                score = float(cvss.get("score")) if cvss.get("score") is not None else None
            except (TypeError, ValueError):
                score = None
            patched = sw.get("patched_versions") or []
            obs.vulns.append(
                Vulnerability(
                    kind,
                    key[1],
                    f"wordfence:{item.get('id')}",
                    str(item.get("title") or "?"),
                    "Wordfence",
                    fixed_in=str(patched[0]) if patched else None,
                    ranges=ranges,
                    score=score,
                    cves=[item["cve"]] if item.get("cve") else [],
                    url=(item.get("references") or [""])[0] if isinstance(item.get("references"), list) else "",
                )
            )


def in_ranges(version: str | None, ranges: list[dict[str, Any]]) -> bool:
    if not version:
        return True
    for r in ranges:
        lo, hi = r.get("from"), r.get("to")
        below = bool(lo and lo != "*") and (
            version_lt(version, lo) or (not r.get("from_inclusive", True) and version == lo)
        )
        above = bool(hi and hi != "*") and (
            version_lt(hi, version) or (not r.get("to_inclusive", True) and version == hi)
        )
        if not below and not above:
            return True
    return False


# ---------------------------------------------------------------------------- GitHub e RSS


def github_release(obs: Observations, settings: Settings, repo: str) -> None:
    headers = {"Accept": "application/vnd.github+json"}
    if settings.watch_github_token.get_secret_value():
        headers["Authorization"] = f"Bearer {settings.watch_github_token.get_secret_value()}"
    try:
        resp = _get(f"https://api.github.com/repos/{repo}/releases/latest", headers=headers)
        obs.requests += 1
        if resp.status_code == 404:
            obs.errors.append(f"GitHub {repo}: sem releases publicadas")
            return
        if resp.status_code == 403:
            obs.errors.append(f"GitHub {repo}: limite de pedidos (define VF_WATCH_GITHUB_TOKEN)")
            return
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        obs.errors.append(f"GitHub {repo}: {exc.__class__.__name__}")
        return
    tag = str(data.get("tag_name") or "").strip()
    if tag:
        obs.releases.append(
            Release("tool", repo, tag, "GitHub", str(data.get("html_url") or ""), str(data.get("published_at") or ""))
        )


_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, load_dtd=False)


def rss(obs: Observations, name: str, url: str, limit: int = 30) -> None:
    try:
        resp = _get(url)
        obs.requests += 1
        resp.raise_for_status()
        root = etree.fromstring(resp.content, parser=_PARSER)  # noqa: S320 — sem entidades nem rede
    except (requests.RequestException, etree.XMLSyntaxError, ValueError) as exc:
        obs.errors.append(f"feed {name}: {exc.__class__.__name__}")
        return
    atom = "{http://www.w3.org/2005/Atom}"
    items = root.findall(".//item") or root.findall(f".//{atom}entry")
    for it in items[:limit]:

        def text(*tags: str, it: Any = it) -> str:
            for t in tags:
                el = it.find(t)
                if el is not None:
                    return (el.text or el.get("href") or "").strip()
            return ""

        title = text("title", f"{atom}title")
        link = text("link", f"{atom}link")
        guid = text("guid", f"{atom}id") or link or title
        if title:
            obs.advisories.append(
                Advisory(name, f"{name}:{guid}", title, link, text("pubDate", f"{atom}updated", f"{atom}published"))
            )


def parse_feeds(value: str) -> list[tuple[str, str]]:
    """ "CERT=https://...; Fornecedor=https://..." → [(nome, url)]."""
    out = []
    for part in value.replace("\n", ";").split(";"):
        if "=" in part:
            name, url = part.split("=", 1)
            if url.strip().startswith(("https://", "http://")):
                out.append((name.strip(), url.strip()))
    return out
