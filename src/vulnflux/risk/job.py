"""Job de prioridades: atualizar feeds → ler findings → calcular → escrever no DefectDojo.

Aparece em Execuções como qualquer outra corrida (fonte "Prioridades"), com passos,
avisos e erros. O resultado (contagens e a lista dos findings mais urgentes) fica no
estado `risk_summary` para a página Prioridades e para o Portal SOC.
"""

from __future__ import annotations

import logging
from typing import Any

from vulnflux import events
from vulnflux.config import Settings
from vulnflux.defectdojo import DefectDojo
from vulnflux.errors import ErrorKind, VFError
from vulnflux.models import ALL_HOSTS, Host, Run, Source, Trigger, utcnow
from vulnflux.risk.enrich import TOP_LIMIT, enrich
from vulnflux.risk.feeds import FeedCache
from vulnflux.store import JsonStore

log = logging.getLogger(__name__)


def create_risk_run(store: JsonStore, trigger: Trigger, hosts: list[Host] | None = None) -> Run | None:
    active = store.active_run(ALL_HOSTS, Source.RISK)
    if active is not None:
        return None
    label = "Todos os hosts" if hosts is None else ", ".join(h.name for h in hosts)[:120]
    run = Run(host_id=ALL_HOSTS, host_name=label, source=Source.RISK, trigger=trigger)
    if hosts is not None:
        run.stats["host_ids"] = [h.id for h in hosts]
    store.save_run(run)
    return run


def execute_risk(
    store: JsonStore,
    settings: Settings,
    run_id: str,
    *,
    download: bool = True,
    dd: DefectDojo | None = None,
    cache: FeedCache | None = None,
) -> Run | None:
    from vulnflux.pipeline import RunRecorder, _internal

    run = store.get_run(run_id)
    if run is None or run.status.finished:
        return run
    rec = RunRecorder(store, run, settings)
    rec.start()
    cache = cache or FeedCache(settings, store)
    try:
        if download:
            with rec.step("Atualizar feeds") as st:
                metas = cache.update_all()
                ok = [m.id for m in metas.values() if not m.error]
                bad = [f"{m.id}: {m.error}" for m in metas.values() if m.error]
                st.detail = f"atualizados: {', '.join(ok) or 'nenhum'}" + (
                    f" · falharam: {'; '.join(bad)}" if bad else ""
                )
                for b in bad:
                    run.warnings.append(f"feed {b} (usa a cópia anterior, se existir)")
                run.stats["feeds"] = {m.id: {"count": m.count, "error": m.error} for m in metas.values()}
        if not cache.available():
            raise VFError(
                ErrorKind.DEPENDENCY,
                "sem dados de ameaça em cache (KEV/EPSS/Exploit-DB): nenhum feed foi descarregado ainda",
            )

        ids = run.stats.get("host_ids")
        hosts = store.list_hosts()
        if ids is not None:
            hosts = [h for h in hosts if h.id in ids]
        hosts = [h for h in hosts if h.enabled]

        with rec.step("Calcular e escrever no DefectDojo") as st:
            dd = dd or DefectDojo(settings)

            def progress(msg: str) -> None:
                st.detail = msg
                rec.save()

            result = enrich(settings, dd, cache, hosts, progress=progress)
            st.detail = f"{result.findings} findings · {result.updated} atualizados · {result.unchanged} sem alterações"
        stats = result.to_dict()
        top = stats.pop("top")
        alerts = stats.pop("alerts")
        run.stats.update(
            {
                "findings_total": result.findings,
                "updated": result.updated,
                "by_priority": result.by_priority,
                "kev": result.kev,
                "products_missing": result.products_missing,
                "manual_sla": result.manual_sla,
                "errors": result.errors,
            }
        )
        if result.products_missing:
            run.warnings.append(
                f"{len(result.products_missing)} host(s) ainda sem product no DefectDojo (sem nenhum import): "
                + ", ".join(result.products_missing[:10])
            )
        if result.errors:
            run.warnings.append(f"{result.errors} finding(s) não atualizados: " + " | ".join(result.error_samples))
        scope = [h.name for h in hosts] if ids is not None else None
        save_summary(store, stats, top, scope)
        events.save_exposure(store, alerts, scope)
        run.stats["events"] = events.findings(store, settings, alerts)
        rec.finish_ok()
    except VFError as exc:
        rec.fail(exc)
    except Exception as exc:
        log.exception("job de prioridades falhou")
        rec.fail(_internal(exc))
    final = store.get_run(run_id)
    if final is not None and ids_is_global(final):
        store.set_state(
            "risk_last",
            {
                "status": {"success": "ok", "warning": "warn"}.get(final.status.value, "fail"),
                "finished_at": final.finished_at.isoformat() if final.finished_at else None,
                "run_id": final.id,
            },
        )
    return final


def save_summary(store: JsonStore, stats: dict[str, Any], top: list[dict[str, Any]], hosts: list[str] | None) -> None:
    """Resumo para a página Prioridades. Com `hosts`, substitui só as linhas desses hosts."""
    summary = store.get_state("risk_summary", {}) or {}
    if hosts is not None and summary.get("stats"):
        names = set(hosts)
        kept = [t for t in summary.get("top", []) if t["host"] not in names]
        top = sorted(kept + top, key=lambda t: (-t["score"], t["planned"]))[:TOP_LIMIT]
        per_host = {k: v for k, v in summary["stats"].get("per_host", {}).items() if k not in names}
        per_host.update(stats.get("per_host", {}))
        stats = {**summary["stats"], "per_host": per_host, "by_priority": _sum_priorities(per_host)}
        generated_at = summary.get("generated_at")
    else:
        generated_at = utcnow().isoformat()
    store.set_state(
        "risk_summary",
        {"generated_at": generated_at, "updated_at": utcnow().isoformat(), "stats": stats, "top": top},
    )


def ids_is_global(run: Run) -> bool:
    return run.stats.get("host_ids") is None


def _sum_priorities(per_host: dict[str, dict[str, int]]) -> dict[str, int]:
    out = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for counts in per_host.values():
        for k, v in counts.items():
            out[k] = out.get(k, 0) + int(v)
    return out


def recalc_host(store: JsonStore, settings: Settings, host: Host, dd: DefectDojo) -> str | None:
    """Fim de um import: recalcula as prioridades desse host com os feeds em cache.

    Devolve o resumo para o detalhe do passo, ou None se não houver feeds (o job
    diário trata disso). Erros sobem como VFError: quem chama decide (é um aviso).
    """
    if not (settings.risk_enabled and settings.risk_after_import):
        return None
    cache = FeedCache(settings, store)
    if not cache.available():
        return None
    result = enrich(settings, dd, cache, [host])
    stats = result.to_dict()
    top = stats.pop("top")
    alerts = stats.pop("alerts")
    save_summary(store, stats, top, [host.name])
    events.save_exposure(store, alerts, [host.name])
    events.findings(store, settings, alerts)
    p = result.by_priority
    return f"P1 {p['P1']} · P2 {p['P2']} · P3 {p['P3']} · P4 {p['P4']} · {result.updated} atualizados no DefectDojo"
