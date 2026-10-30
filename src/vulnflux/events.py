"""Eventos do SOC: o que o VulnFlux tem de dizer a pessoas e ao SIEM.

Três tipos, cada um enviado uma só vez (há memória do que já foi enviado):

  vulnerabilidade   finding novo em P1 ou na lista KEV (explorado no terreno)
  servidor          um servidor passou a crítico ou deixou de responder
  execucao          um scan, import ou verificação falhou

Destinos, todos opcionais e independentes:

  ficheiro  data_dir/eventos/eventos.jsonl, uma linha JSON por evento (sempre ligado). O agente do
            SIEM (AMA, Wazuh, WinCollect, Filebeat…) lê o ficheiro: zero configuração no VulnFlux.
  syslog    VF_EVENTS_SYSLOG=udp://siem:514 ou tcp://siem:514. RFC 5424 com a mensagem em JSON
            (campos ECS: event.*, host.name, vulnerability.*), fácil de mapear em qualquer SIEM.
  webhook   VF_EVENTS_WEBHOOK_URL. POST JSON com "text" (Teams, Slack, Mattermost) e o evento inteiro.

Um destino em baixo nunca faz falhar o scan: o evento fica no ficheiro com o erro de entrega.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from vulnflux import __version__
from vulnflux.config import Settings
from vulnflux.models import utcnow
from vulnflux.store import JsonStore

log = logging.getLogger(__name__)

SEVERITY = {"critical": (2, 99), "high": (3, 73), "medium": (4, 47), "low": (5, 21), "info": (6, 1)}
FACILITY_LOCAL4 = 20
SEEN_DAYS = 120
KEEP_RECENT = 300
MAX_FILE = 20 * 1024 * 1024
_lock = threading.Lock()


def _event(
    kind: str,
    severity: str,
    title: str,
    *,
    host: str = "",
    data: dict[str, Any] | None = None,
    category: str = "vulnerability",
    settings: Settings | None = None,
) -> dict[str, Any]:
    now = utcnow()
    ev: dict[str, Any] = {
        "@timestamp": now.isoformat(),
        "message": title,
        "event": {
            "kind": "alert",
            "category": [category],
            "type": [kind],
            "severity": SEVERITY.get(severity, SEVERITY["info"])[1],
            "severity_name": severity,
            "provider": "adamastor-soc.vulnflux",
        },
        "observer": {"product": "VulnFlux", "vendor": "Adamastor SOC", "version": __version__},
        "labels": {"soc_tipo": kind},
    }
    if host:
        ev["host"] = {"name": host}
    if settings and settings.base_url:
        ev["url"] = {"original": settings.base_url.rstrip("/")}
    ev.update(data or {})
    return ev


def emit(store: JsonStore, settings: Settings, key: str, ev: dict[str, Any]) -> bool:
    """Envia o evento se a chave ainda não foi vista. Devolve True se foi um evento novo."""
    if not settings.events_enabled:
        return False
    with _lock:
        seen = store.get_state("events_seen", {}) or {}
        if key in seen:
            return False
        now = utcnow()
        cutoff = (now - timedelta(days=SEEN_DAYS)).isoformat()
        seen = {k: v for k, v in seen.items() if v >= cutoff}
        seen[key] = now.isoformat()
        store.set_state("events_seen", seen)
    ev.setdefault("event", {})["id"] = key
    delivery = {}
    if settings.events_syslog.strip():
        delivery["syslog"] = _try(_send_syslog, settings, ev)
    if settings.events_webhook_url.get_secret_value().strip():
        delivery["webhook"] = _try(_send_webhook, settings, ev)
    ev["entrega"] = delivery
    _write_file(settings, ev)
    with _lock:
        recent = store.get_state("events", []) or []
        recent.append(
            {
                "key": key,
                "at": ev["@timestamp"],
                "tipo": ev["event"]["type"][0],
                "gravidade": ev["event"]["severity_name"],
                "titulo": ev["message"],
                "host": ev.get("host", {}).get("name", ""),
                "entrega": delivery,
            }
        )
        store.set_state("events", recent[-KEEP_RECENT:])
    return True


def _try(fn: Any, settings: Settings, ev: dict[str, Any]) -> str:
    try:
        fn(settings, ev)
        return "ok"
    except Exception as exc:  # noqa: BLE001 - um destino em baixo não pode parar o SOC
        log.warning("evento %s não entregue por %s: %s", ev["event"].get("id"), fn.__name__, exc)
        return f"erro: {exc.__class__.__name__}: {str(exc)[:200]}"


def _write_file(settings: Settings, ev: dict[str, Any]) -> None:
    d = Path(settings.data_dir) / "eventos"
    try:
        d.mkdir(parents=True, exist_ok=True)
        f = d / "eventos.jsonl"
        if f.exists() and f.stat().st_size > MAX_FILE:
            f.replace(d / "eventos.jsonl.1")
        with f.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev, ensure_ascii=False, default=str) + "\n")
    except OSError as exc:
        log.warning("não foi possível escrever o ficheiro de eventos: %s", exc)


def syslog_line(ev: dict[str, Any], hostname: str = "vulnflux") -> bytes:
    sev = SEVERITY.get(ev["event"].get("severity_name", "info"), SEVERITY["info"])[0]
    pri = FACILITY_LOCAL4 * 8 + sev
    msgid = ev["event"]["type"][0][:32]
    body = json.dumps({k: v for k, v in ev.items() if k != "entrega"}, ensure_ascii=False, default=str)
    return f"<{pri}>1 {ev['@timestamp']} {hostname} vulnflux - {msgid} - {body}".encode()


def _send_syslog(settings: Settings, ev: dict[str, Any]) -> None:
    u = urlparse(settings.events_syslog.strip())
    if u.scheme not in ("udp", "tcp") or not u.hostname:
        raise ValueError("VF_EVENTS_SYSLOG deve ser udp://host:porta ou tcp://host:porta")
    port = u.port or 514
    line = syslog_line(ev, socket.gethostname()[:64] or "vulnflux")
    if u.scheme == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(line[:8192], (u.hostname, port))
    else:
        with socket.create_connection((u.hostname, port), timeout=10) as s:
            s.sendall(f"{len(line)} ".encode() + line)  # RFC 6587, octet counting


def _send_webhook(settings: Settings, ev: dict[str, Any]) -> None:
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(ev["event"]["severity_name"], "🔵")
    text = f"{icon} Adamastor SOC · {ev['message']}"
    if ev.get("url"):
        text += f"\n{ev['url']['original']}"
    resp = requests.post(settings.events_webhook_url.get_secret_value(), json={"text": text, "evento": ev}, timeout=10)
    resp.raise_for_status()


# ------------------------------------------------------------------ produtores
def _finding_key(it: dict[str, Any]) -> str:
    return f"vuln:{it.get('finding_id')}:{it.get('priority')}:{'kev' if it.get('kev') else ''}"


def findings(store: JsonStore, settings: Settings, items: list[dict[str, Any]]) -> int:
    """Findings em P1 ou KEV. A chave inclui a prioridade: subir a P1 mais tarde volta a avisar.

    Se forem mais do que VF_EVENTS_MAX_PER_RUN de uma vez (primeira execução, host novo grande),
    vai um só evento de resumo em vez de uma avalanche.
    """
    if not settings.events_enabled:
        return 0
    seen = store.get_state("events_seen", {}) or {}
    new = [it for it in items if (it.get("priority") == "P1" or it.get("kev")) and _finding_key(it) not in seen]
    if len(new) > settings.events_max_per_run:
        with _lock:
            seen = store.get_state("events_seen", {}) or {}
            now = utcnow().isoformat()
            seen.update({_finding_key(it): now for it in new})
            store.set_state("events_seen", seen)
        hosts = sorted({it["host"] for it in new})
        kev = sum(1 for it in new if it.get("kev"))
        ev = _event(
            "vulnerabilidade",
            "critical",
            f"{len(new)} findings novos em P1 ou KEV ({kev} KEV) em {len(hosts)} host(s): {', '.join(hosts[:8])}",
            settings=settings,
            data={
                "vulnflux": {
                    "resumo": True,
                    "total": len(new),
                    "kev": kev,
                    "hosts": hosts[:100],
                    "exemplos": [f"{it['host']}: {it['title'][:100]}" for it in new[:20]],
                }
            },
        )
        return int(emit(store, settings, f"vuln-resumo:{utcnow().isoformat()}", ev))
    sent = 0
    for it in new:
        why = "KEV (explorada no terreno)" if it.get("kev") else "prioridade P1"
        cves = it.get("cves") or []
        ev = _event(
            "vulnerabilidade",
            "critical",
            f"{it['host']}: {it['title'][:140]} · {why}",
            host=it["host"],
            settings=settings,
            data={
                "vulnerability": {
                    "id": cves[:5],
                    "severity": it.get("severity"),
                    "classification": "CVE" if cves else "",
                    "score": {"base": it.get("score")},
                },
                "vulnflux": {
                    "finding_id": it.get("finding_id"),
                    "prioridade": it.get("priority"),
                    "kev": bool(it.get("kev")),
                    "exploits": it.get("exploits"),
                    "epss_percentil": it.get("epss_percentile"),
                    "corrigir_ate": it.get("planned"),
                    "razoes": it.get("reasons"),
                },
            },
        )
        sent += emit(store, settings, _finding_key(it), ev)
    return sent


def server(store: JsonStore, settings: Settings, host: Any, status: str, summary: str) -> bool:
    """Servidor crítico ou inacessível: avisa na transição (não a cada verificação)."""
    last = store.get_state("events_server_status", {}) or {}
    prev = last.get(host.id)
    last[host.id] = status
    store.set_state("events_server_status", last)
    if status not in ("fail", "unreachable") or prev == status:
        return False
    title = f"{host.name}: " + ("deixou de responder por SSH" if status == "unreachable" else "estado crítico")
    ev = _event(
        "servidor",
        "high",
        f"{title} · {summary[:200]}",
        host=host.name,
        category="host",
        settings=settings,
        data={"vulnflux": {"estado": status, "resumo": summary[:500]}},
    )
    return emit(store, settings, f"server:{host.id}:{status}:{utcnow().isoformat()}", ev)


def run_failed(store: JsonStore, settings: Settings, run: Any) -> bool:
    ev = _event(
        "execucao",
        "medium",
        f"{run.source.value} falhou em {run.host_name}: {run.error_message or '?'}"[:300],
        host=run.host_name if "," not in run.host_name else "",
        category="process",
        settings=settings,
        data={
            "vulnflux": {
                "execucao": run.id,
                "fonte": run.source.value,
                "tipo_erro": getattr(run.error_kind, "value", None),
            }
        },
    )
    return emit(store, settings, f"run:{run.id}", ev)


# ------------------------------------------------------------------ exposição para o SIEM
def save_exposure(store: JsonStore, items: list[dict[str, Any]], hosts: list[str] | None) -> None:
    """Lista de exposição (P1, P2 e KEV por host) para a watchlist do SIEM. Com `hosts`, só esses mudam."""
    keep = [x for x in items if x.get("priority") in ("P1", "P2") or x.get("kev")]
    rows = [
        {
            "host": x["host"],
            "cve": ",".join(x.get("cves") or []),
            "prioridade": x.get("priority"),
            "kev": bool(x.get("kev")),
            "epss_percentil": x.get("epss_percentile"),
            "titulo": x.get("title", "")[:160],
            "corrigir_ate": x.get("planned"),
            "finding_id": x.get("finding_id"),
        }
        for x in keep
    ]
    current = store.get_state("exposure", {}) or {}
    if hosts is not None:
        names = set(hosts)
        rows = [r for r in current.get("rows", []) if r["host"] not in names] + rows
    rows.sort(key=lambda r: (r["prioridade"] or "P9", not r["kev"], r["host"]))
    store.set_state("exposure", {"updated_at": utcnow().isoformat(), "rows": rows[:5000]})
