"""Ciclos de atualização por anéis.

    Anel 0 · Canário   servidores que se pode partir (laboratório, testes)
    Anel 1 · Piloto    uma amostra representativa
    Anel 2 · Geral     o resto
    Anel 3 · Críticos  só com aprovação de uma pessoa

Um anel só começa quando o anterior terminou bem e passou o tempo de observação
(VF_PATCH_SOAK_HOURS). Se um servidor de um anel falha (atualização com erro, não volta depois do
reinício, serviços que deixam de arrancar), o ciclo para: os anéis seguintes não são tocados até
alguém ver o que aconteceu. Servidores em "só verificar" nunca são atualizados.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Any

from vulnflux.config import Settings
from vulnflux.models import Run, RunStatus, Source, Trigger, new_id, utcnow
from vulnflux.pipeline import create_run
from vulnflux.store import JsonStore

RINGS = [(0, "Canário"), (1, "Piloto"), (2, "Geral"), (3, "Críticos")]
RING_HELP = {
    0: "Os primeiros: servidores de laboratório ou de testes, que se pode partir.",
    1: "Uma amostra de cada tipo de servidor, para apanhar problemas antes do geral.",
    2: "A maioria dos servidores.",
    3: "Produção crítica: só avança com aprovação explícita.",
}
ACTIVE = "a_decorrer"


def _dt(v: Any) -> datetime | None:
    if not v:
        return None
    if isinstance(v, datetime):
        return v
    try:
        return datetime.fromisoformat(str(v))
    except ValueError:
        return None


def active_cycle(store: JsonStore) -> dict[str, Any] | None:
    return next((c for c in store.list_cycles() if c.get("status") == ACTIVE), None)


def new_cycle(
    store: JsonStore, settings: Settings, trigger: Trigger, actor: str = "agendamento"
) -> dict[str, Any] | None:
    """Cria um ciclo com os servidores de cada anel (fotografia do momento). None se já houver um a decorrer."""
    if active_cycle(store):
        return None
    hosts = [h for h in store.list_hosts() if h.source_enabled(Source.SERVER)]
    rings = []
    for idx, name in RINGS:
        members = [h for h in hosts if h.patch_ring == idx]
        servers = [
            {
                "host_id": h.id,
                "name": h.name,
                "mode": h.patch_mode,
                "status": "pendente" if h.source_enabled(Source.PATCH) else "so_verificar",
                "run_id": None,
                "detail": "",
            }
            for h in sorted(members, key=lambda x: x.name)
        ]
        patchable = any(s["status"] == "pendente" for s in servers)
        rings.append(
            {
                "ring": idx,
                "name": name,
                "status": "por_iniciar" if patchable else "vazio",
                "servers": servers,
                "started_at": None,
                "finished_at": None,
                "opens_at": None,
                "approved_by": None,
            }
        )
    cycle = {
        "id": new_id(),
        "created_at": utcnow().isoformat(),
        "trigger": trigger.value,
        "created_by": actor,
        "status": ACTIVE,
        "soak_hours": settings.patch_soak_hours,
        "rings": rings,
        "finished_at": None,
        "note": "",
    }
    if not any(r["status"] == "por_iniciar" for r in rings):
        cycle.update(
            status="concluido",
            finished_at=utcnow().isoformat(),
            note="Nenhum servidor em modo de atualização (todos em 'só verificar').",
        )
    store.save_cycle(cycle)
    return cycle


def advance(
    store: JsonStore, settings: Settings, start_ring: Callable[[str, int], None], now: datetime | None = None
) -> dict[str, Any] | None:
    """Avança o ciclo a decorrer: começa o próximo anel quando o portão abre. Idempotente."""
    cycle = active_cycle(store)
    if cycle is None:
        return None
    now = now or utcnow()
    soak = timedelta(hours=float(cycle.get("soak_hours") or settings.patch_soak_hours))
    last_done: datetime | None = None
    for idx, ring in enumerate(cycle["rings"]):
        st = ring["status"]
        if st == "vazio":
            continue
        if st == "ok":
            last_done = _dt(ring["finished_at"]) or last_done
            continue
        if st == "falhou":
            cycle.update(
                status="parado",
                note=f"Parado: o anel {ring['ring']} ({ring['name']}) falhou. Os anéis seguintes não foram tocados.",
            )
            store.save_cycle(cycle)
            return cycle
        if st == "a_correr":
            return cycle
        # por_iniciar · aguarda_observacao · aguarda_aprovacao
        if last_done and now - last_done < soak:
            ring.update(status="aguarda_observacao", opens_at=(last_done + soak).isoformat())
            store.save_cycle(cycle)
            return cycle
        if ring["ring"] == 3 and settings.patch_ring3_approval and not ring.get("approved_by"):
            ring.update(status="aguarda_aprovacao", opens_at=None)
            store.save_cycle(cycle)
            return cycle
        ring.update(status="a_correr", started_at=now.isoformat(), opens_at=None)
        store.save_cycle(cycle)
        start_ring(cycle["id"], idx)
        return cycle
    cycle.update(status="concluido", finished_at=now.isoformat())
    store.save_cycle(cycle)
    return cycle


def approve(store: JsonStore, cycle_id: str, ring_index: int, user: str) -> bool:
    cycle = store.get_cycle(cycle_id)
    if not cycle or cycle.get("status") != ACTIVE:
        return False
    ring = cycle["rings"][ring_index]
    if ring["status"] not in ("aguarda_aprovacao", "por_iniciar", "aguarda_observacao"):
        return False
    ring["approved_by"] = user
    ring["approved_at"] = utcnow().isoformat()
    store.save_cycle(cycle)
    return True


def cancel(store: JsonStore, cycle_id: str, user: str) -> bool:
    cycle = store.get_cycle(cycle_id)
    if not cycle or cycle.get("status") not in (ACTIVE, "parado"):
        return False
    if any(r["status"] == "a_correr" for r in cycle["rings"]):
        return False  # não se cancela a meio de um anel: espera que acabe
    cycle.update(status="cancelado", finished_at=utcnow().isoformat(), note=f"Cancelado por {user}.")
    store.save_cycle(cycle)
    return True


def resume(store: JsonStore, cycle_id: str, user: str) -> bool:
    """Depois de ver o que falhou: repetir o anel que falhou."""
    cycle = store.get_cycle(cycle_id)
    if not cycle or cycle.get("status") != "parado" or active_cycle(store):
        return False
    for ring in cycle["rings"]:
        if ring["status"] == "falhou":
            ring.update(status="por_iniciar", finished_at=None)
            for s in ring["servers"]:
                if s["status"] in ("falhou", "nao_tentado"):
                    s.update(status="pendente", run_id=None, detail="")
    cycle.update(status=ACTIVE, note=f"Retomado por {user}.")
    store.save_cycle(cycle)
    return True


def run_ring(
    store: JsonStore,
    settings: Settings,
    cycle_id: str,
    ring_index: int,
    execute: Callable[[str], Run | None],
    trigger: Trigger = Trigger.SCHEDULE,
) -> dict[str, Any] | None:
    """Atualiza os servidores de um anel (em paralelo, até VF_SERVERS_CONCURRENCY) e fecha o anel."""
    cycle = store.get_cycle(cycle_id)
    if cycle is None:
        return None
    ring = cycle["rings"][ring_index]
    todo = []
    for s in ring["servers"]:
        if s["status"] != "pendente":
            continue
        host = store.get_host(s["host_id"])
        if host is None or not host.source_enabled(Source.PATCH):
            s.update(status="so_verificar", detail="mudou para 'só verificar' ou foi removido")
            continue
        run = create_run(store, host, Source.PATCH, trigger)
        if run is None:
            s.update(status="falhou", detail="já havia uma atualização em curso neste servidor")
            continue
        run.stats.update(cycle_id=cycle_id, ring=ring["ring"])
        store.save_run(run)
        s.update(status="a_correr", run_id=run.id)
        todo.append(s)
    store.save_cycle(cycle)

    def one(server: dict[str, Any]) -> tuple[str, Run | None]:
        return server["host_id"], execute(server["run_id"])

    with ThreadPoolExecutor(max_workers=max(1, settings.servers_concurrency), thread_name_prefix="vf-patch") as pool:
        results = dict(pool.map(one, todo))

    cycle = store.get_cycle(cycle_id) or cycle
    ring = cycle["rings"][ring_index]
    failed = 0
    for s in ring["servers"]:
        if s["host_id"] not in results:
            continue
        run = results[s["host_id"]]
        if run is not None and run.status in (RunStatus.SUCCESS, RunStatus.WARNING):
            nothing = run.stats.get("nothing_to_do")
            s.update(
                status="ok",
                detail="nada a atualizar"
                if nothing
                else f"segurança {run.stats.get('before_security', '?')} → {run.stats.get('after_security', '?')}"
                + (" · reiniciado" if run.stats.get("rebooted") else ""),
            )
        else:
            failed += 1
            s.update(status="falhou", detail=(run.error_message if run else "execução perdida") or "falhou")
    ring.update(status="falhou" if failed else "ok", finished_at=utcnow().isoformat())
    store.save_cycle(cycle)
    return cycle
