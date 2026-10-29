"""Estado do VulnFlux no contrato soc-status/1 (lido pelo Portal SOC).

O contrato (docs/soc-status.md) é deliberadamente simples para que qualquer serviço
novo do SOC o possa publicar: estado, verificações, dependências, listas/feeds com a
data da última atualização, componentes e tarefas agendadas.

Só lê o que já está no store (resultados das verificações de saúde e dos jobs): pedir
o estado nunca dispara chamadas ao DefectDojo, ao Greenbone ou à Internet.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from vulnflux import __version__
from vulnflux.collectors import wpscan
from vulnflux.config import Settings
from vulnflux.greenbone.readiness import REQUIRED_FEEDS, parse_feed_timestamp
from vulnflux.models import Source
from vulnflux.store import JsonStore

SCHEMA = "soc-status/1"
_RANK = {"ok": 0, "off": 1, "unknown": 2, "warn": 3, "fail": 4}

# Idade máxima aceitável de cada lista (horas) antes de o portal a mostrar como desatualizada
WPSCAN_DB_MAX_AGE_H = 36
RISK_MAX_AGE_H = {"kev": 48, "epss": 48, "exploitdb": 24 * 7, "metasploit": 24 * 7, "nuclei": 24 * 7}

GB_FEED_NAMES = {
    "NVT": "NVT · testes de vulnerabilidade",
    "SCAP": "SCAP · CVE e CPE",
    "CERT": "CERT · avisos de segurança",
    "GVMD_DATA": "GVMD_DATA · configurações e listas de portas",
}


def _status(value: Any) -> str:
    text = str(value or "unknown")
    return text if text in _RANK else "unknown"


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _greenbone_component(settings: Settings, store: JsonStore, health: dict[str, Any]) -> dict[str, Any]:
    h = health.get("greenbone") or {}
    status = _status(h.get("status")) if settings.greenbone_enabled else "off"
    snapshot = store.get_state("greenbone_feeds", {}) or {}
    versions: dict[str, str] = snapshot.get("versions") or {}
    syncing = set(snapshot.get("syncing") or [])
    max_age = settings.greenbone_max_feed_age_days * 24
    freshness = []
    for feed in REQUIRED_FEEDS:
        version = versions.get(feed)
        ts = parse_feed_timestamp(version or "")
        item: dict[str, Any] = {
            "id": f"greenbone_{feed.lower()}",
            "name": GB_FEED_NAMES.get(feed, feed),
            "updated_at": _iso(ts),
            "max_age_hours": max_age,
            "version": version,
        }
        if feed in syncing:
            item["status"], item["message"] = "warn", "a carregar no gvmd"
        elif not version:
            item["status"], item["message"] = "unknown", "ainda não observado (o Greenbone ainda não arrancou?)"
        elif status == "off":
            # Parado de propósito: os feeds atualizam no arranque da próxima janela de scan.
            item["status"] = "off"
            item["message"] = "atualiza no início da próxima janela de scan"
        else:
            item["status"] = "ok"
        if snapshot.get("observed_at"):
            item["observed_at"] = snapshot["observed_at"]
        freshness.append(item)
    readiness = (h.get("details") or {}).get("readiness") or {}
    return {
        "name": "Greenbone",
        "status": status,
        "message": h.get("message") or ("desativado" if not settings.greenbone_enabled else "por verificar"),
        "version": f"GMP {readiness['gmp_version']}" if readiness.get("gmp_version") else None,
        "checks": [
            {
                "id": c.get("name"),
                "name": c.get("name"),
                "status": "ok" if c.get("ok") else "warn",
                "message": c.get("detail"),
            }
            for c in readiness.get("checks", [])
        ],
        "freshness": freshness,
    }


def _risk_freshness(settings: Settings, store: JsonStore) -> list[dict[str, Any]]:
    from vulnflux.risk.feeds import FEED_NAMES, FeedCache

    if not settings.risk_enabled:
        return []
    feeds = store.get_state("risk_feeds", {}) or {}
    out = []
    for fid, url in FeedCache.urls_for(settings).items():
        if not url:
            continue
        f = feeds.get(fid) or {"name": FEED_NAMES[fid]}
        if not f.get("fetched_at"):
            out.append(
                {
                    "id": f"risk_{fid}",
                    "name": f.get("name") or FEED_NAMES[fid],
                    "updated_at": None,
                    "max_age_hours": RISK_MAX_AGE_H.get(fid, 48),
                    "status": "fail" if f.get("error") else "unknown",
                    "message": f.get("error") or "ainda não descarregado (job diário de prioridades)",
                }
            )
            continue
        status = "fail" if f.get("error") else "ok"
        out.append(
            {
                "id": f"risk_{fid}",
                "name": f.get("name") or fid,
                "updated_at": f.get("source_date") or f.get("fetched_at"),
                "max_age_hours": RISK_MAX_AGE_H.get(fid, 48),
                "status": status,
                "message": f.get("error") or (f"{f['count']} entradas" if f.get("count") is not None else ""),
                "count": f.get("count"),
            }
        )
    return out


def _last_run(store: JsonStore, source: Source) -> tuple[str | None, str | None]:
    runs = [r for r in store.list_runs(source=source, limit=20) if r.status.finished]
    if not runs:
        return None, None
    r = runs[0]
    mapping = {"success": "ok", "warning": "warn", "failed": "fail", "interrupted": "fail", "skipped": "warn"}
    return mapping.get(r.status.value, "unknown"), _iso(r.finished_at)


def build_status(
    settings: Settings,
    store: JsonStore,
    next_runs: list[dict[str, Any]] | None = None,
    schedule_errors: dict[str, str] | None = None,
) -> dict[str, Any]:
    health: dict[str, Any] = store.get_state("health", {}) or {}
    checks = [
        {
            "id": key,
            "name": h.get("label", key),
            "status": _status(h.get("status")),
            "message": h.get("message", ""),
            "checked_at": h.get("checked_at"),
        }
        for key, h in health.items()
    ]
    for job_id, err in (schedule_errors or {}).items():
        checks.append({"id": f"schedule_{job_id}", "name": f"Agendamento {job_id}", "status": "fail", "message": err})

    greenbone = _greenbone_component(settings, store, health)

    db_at = wpscan.database_updated_at(settings)
    freshness = [
        {
            "id": "wpscan_db",
            "name": "WPScan · base de dados de vulnerabilidades",
            "updated_at": _iso(db_at),
            "max_age_hours": WPSCAN_DB_MAX_AGE_H,
            "status": "ok" if db_at else "unknown",
            "message": "" if db_at else "ainda não descarregada (atualiza antes do 1.º lote)",
        }
    ]
    freshness += _risk_freshness(settings, store)

    risk_state = store.get_state("risk_last", {}) or {}
    jobs = []
    last_by_job = {
        "wpscan_batch": _last_run(store, Source.WPSCAN),
        "greenbone_batch": _last_run(store, Source.GREENBONE),
        "risk_daily": (risk_state.get("status"), risk_state.get("finished_at")),
    }
    for job in next_runs or []:
        if job["id"] in ("health", "purge"):
            continue
        last_status, last_at = last_by_job.get(job["id"], (None, None))
        jobs.append(
            {
                "id": job["id"],
                "name": job["name"],
                "next_run": _iso(job.get("next")),
                "last_status": last_status,
                "last_finished": last_at,
            }
        )

    dependencies = {
        "defectdojo": _status((health.get("defectdojo") or {}).get("status")),
        "greenbone": greenbone["status"],
        "wpscan-api": _status((health.get("wpscan_api") or {}).get("status")),
    }

    problems = [c for c in checks if c["status"] in ("warn", "fail")]
    if any(c["id"].startswith("schedule_") for c in problems):
        status, message = (
            "fail",
            "agendamento inválido: " + "; ".join(c["message"] for c in problems if c["id"].startswith("schedule_")),
        )
    elif not health:
        status, message = "unknown", "verificações de saúde ainda não correram"
    elif problems:
        # O VulnFlux está a funcionar; é uma dependência que tem problemas.
        status, message = "warn", "com problemas: " + ", ".join(c["name"] for c in problems)
    else:
        status, message = "ok", "operacional"

    return {
        "schema": SCHEMA,
        "service": "vulnflux",
        "version": __version__,
        "status": status,
        "message": message,
        "generated_at": _iso(datetime.now().astimezone()),
        "checks": checks,
        "dependencies": dependencies,
        "freshness": freshness,
        "components": {"greenbone": greenbone},
        "jobs": jobs,
    }
