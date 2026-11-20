"""Que hosts são WordPress? Verificação rápida e sem chave, antes de gastar tempo com o WPScan.

Para cada host com URL (ou, sem URL, https://<nome>/ quando o nome é um domínio), pede a página
inicial e procura sinais do WordPress. Se a página não chegar para decidir, tenta /wp-json/ e
/wp-login.php. Cada sinal fica registado como evidência, para se perceber porque foi classificado.

  forte   cabeçalho Link com api.w.org, /wp-json/ com o namespace wp/v2, formulário do wp-login.php
  média   referências a /wp-content/ ou /wp-includes/ no HTML, meta generator "WordPress x.y"
"""

from __future__ import annotations

import ipaddress
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from vulnflux.config import Settings
from vulnflux.models import Host, utcnow
from vulnflux.store import JsonStore

log = logging.getLogger(__name__)

STATE_KEY = "wp_detect"
UA = "Mozilla/5.0 (compatible; Vigia-Adamastor/1.0; +verificacao-wordpress)"
_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]*)', re.IGNORECASE)
_ASSETS = re.compile(r"/wp-(?:content|includes)/", re.IGNORECASE)
_MAX_BODY = 600_000


def target_url(host: Host) -> str | None:
    if host.url:
        return host.url
    name = host.name.strip().lower()
    if "." not in name:
        return None
    try:
        ipaddress.ip_address(name)
        return None  # um IP não diz que site é: precisa de URL
    except ValueError:
        return f"https://{name}/"


def _get(session: requests.Session, url: str, settings: Settings) -> requests.Response:
    return session.get(
        url,
        timeout=(6, 12),
        allow_redirects=True,
        verify=not settings.wpscan_disable_tls_checks,
        headers={"User-Agent": UA, "Accept": "text/html,application/json;q=0.9,*/*;q=0.5"},
        stream=True,
    )


def _body(resp: requests.Response) -> str:
    chunks, size = [], 0
    for chunk in resp.iter_content(chunk_size=32_768, decode_unicode=False):
        chunks.append(chunk)
        size += len(chunk)
        if size >= _MAX_BODY:
            break
    resp.close()
    return b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")


def detect(url: str, settings: Settings, session: requests.Session | None = None) -> dict[str, Any]:
    session = session or requests.Session()
    out: dict[str, Any] = {"url": url, "checked_at": utcnow().isoformat(), "evidence": [], "version": None}
    strong = medium = 0
    try:
        resp = _get(session, url, settings)
        out["final_url"] = resp.url
        out["http"] = resp.status_code
        link = resp.headers.get("Link", "")
        body = _body(resp)
    except requests.RequestException as exc:
        out.update(is_wp=None, error=f"sem resposta: {exc.__class__.__name__}")
        return out

    if "api.w.org" in link:
        strong += 1
        out["evidence"].append("cabeçalho Link aponta para a API do WordPress (api.w.org)")
    m = _GENERATOR.search(body)
    if m:
        medium += 1
        out["version"] = m.group(1) or None
        out["evidence"].append(f"meta generator WordPress {m.group(1)}".strip())
    assets = len(_ASSETS.findall(body))
    if assets:
        medium += 1
        out["evidence"].append(f"{assets} referências a /wp-content/ ou /wp-includes/")

    base = out.get("final_url") or url
    if strong == 0 and medium < 2:
        # A página inicial não chega (cache, CDN, tema sem rasto): confirma pelos endereços próprios.
        try:
            r = _get(session, urljoin(base, "/wp-json/"), settings)
            text = _body(r)
            if r.status_code == 200 and '"wp/v2"' in text:
                strong += 1
                out["evidence"].append("/wp-json/ responde com o namespace wp/v2")
        except requests.RequestException:
            pass
    if strong == 0 and medium < 2:
        try:
            r = _get(session, urljoin(base, "/wp-login.php"), settings)
            text = _body(r)
            if r.status_code in (200, 403) and ("user_login" in text or "wp-submit" in text):
                strong += 1
                out["evidence"].append("/wp-login.php tem o formulário de entrada do WordPress")
        except requests.RequestException:
            pass

    if strong or medium >= 2:
        out["is_wp"] = True
    elif medium == 1:
        out["is_wp"] = True
        out["evidence"].append("sinal fraco: confirmar")
        out["weak"] = True
    else:
        out["is_wp"] = False
        if out.get("http", 200) >= 400:
            out["evidence"].append(f"página inicial respondeu HTTP {out['http']}")
        else:
            out["evidence"].append("nenhum sinal do WordPress na página inicial, em /wp-json/ nem em /wp-login.php")
    if urlparse(base).netloc and urlparse(base).netloc != urlparse(url).netloc:
        out["evidence"].append(f"redireciona para {urlparse(base).netloc}")
    return out


def run(store: JsonStore, settings: Settings, host_ids: list[str] | None = None, workers: int = 8) -> dict[str, Any]:
    """Verifica os hosts (todos, ou os indicados) e guarda o resultado em store state wp_detect."""
    hosts = [h for h in store.list_hosts() if h.enabled and (host_ids is None or h.id in host_ids)]
    jobs = [(h, target_url(h)) for h in hosts]
    jobs = [(h, u) for h, u in jobs if u]
    results: dict[str, dict[str, Any]] = {}

    def one(item: tuple[Host, str]) -> tuple[str, dict[str, Any]]:
        host, url = item
        try:
            return host.id, detect(url, settings)
        except Exception as exc:  # um host estranho não pode parar os outros
            log.exception("deteção WordPress falhou em %s", url)
            return host.id, {
                "url": url,
                "is_wp": None,
                "error": f"erro interno: {exc.__class__.__name__}",
                "evidence": [],
                "checked_at": utcnow().isoformat(),
            }

    with ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="vf-wpdetect") as pool:
        for hid, res in pool.map(one, jobs):
            results[hid] = res
    with store.locked():
        data = store.get_state(STATE_KEY, {}) or {}
        data.update(results)
        known = {h.id for h in store.list_hosts()}
        data = {k: v for k, v in data.items() if k in known}
        store.set_state(STATE_KEY, data)
    summary = {
        "at": utcnow().isoformat(),
        "checked": len(results),
        "wordpress": sum(1 for r in results.values() if r.get("is_wp")),
        "not_wordpress": sum(1 for r in results.values() if r.get("is_wp") is False),
        "no_answer": sum(1 for r in results.values() if r.get("is_wp") is None),
    }
    store.set_state("wp_detect_last", summary)
    return summary


def is_known_not_wp(store: JsonStore, host_id: str, max_age_days: int = 7) -> bool:
    """Classificado como não-WordPress há menos de max_age_days: o lote WPScan salta-o."""
    res = (store.get_state(STATE_KEY, {}) or {}).get(host_id)
    if not res or res.get("is_wp") is not False:
        return False
    from datetime import datetime, timedelta

    try:
        return utcnow() - datetime.fromisoformat(res["checked_at"]) < timedelta(days=max_age_days)
    except (KeyError, ValueError):
        return False
