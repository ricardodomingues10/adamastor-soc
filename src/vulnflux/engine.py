"""Motor: agendamento e filas de execução.

Duas filas independentes (um worker cada), para um lote do Greenbone de várias horas
não bloquear os scans WPScan diários. Dentro de cada fila as execuções são em série.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from vulnflux import pipeline
from vulnflux.config import Settings
from vulnflux.health import check_all
from vulnflux.models import Host, Run, Source, Trigger
from vulnflux.risk.job import create_risk_run, execute_risk
from vulnflux.servers import cycles as patch_cycles
from vulnflux.servers import job as servers_job
from vulnflux.store import JsonStore

log = logging.getLogger(__name__)


class Engine:
    def __init__(self, settings: Settings, store: JsonStore, *, start_scheduler: bool = True) -> None:
        self.settings = settings
        self.store = store
        self._start_scheduler = start_scheduler
        self.lanes = {
            "wpscan": ThreadPoolExecutor(max_workers=1, thread_name_prefix="vf-wpscan"),
            "greenbone": ThreadPoolExecutor(max_workers=1, thread_name_prefix="vf-greenbone"),
            "misc": ThreadPoolExecutor(max_workers=1, thread_name_prefix="vf-misc"),
            "risk": ThreadPoolExecutor(max_workers=1, thread_name_prefix="vf-risk"),
            "servers": ThreadPoolExecutor(
                max_workers=max(1, settings.servers_concurrency), thread_name_prefix="vf-servers"
            ),
            "patch": ThreadPoolExecutor(max_workers=1, thread_name_prefix="vf-patch-ring"),
        }
        self._busy: dict[str, int] = {name: 0 for name in self.lanes}
        self._lock = threading.Lock()
        self.scheduler = BackgroundScheduler(timezone=settings.timezone)
        self.schedule_errors: dict[str, str] = {}

    # ------------------------------------------------------------------ ciclo de vida
    def start(self) -> None:
        recovered = self.store.recover_interrupted()
        if recovered:
            log.warning("%d execuções marcadas como interrompidas após reinício", recovered)
        purged = self.store.purge_older_than(self.settings.retention_days)
        if purged:
            log.info("%d execuções antigas removidas (retenção %d dias)", purged, self.settings.retention_days)
        if not self._start_scheduler:
            return
        self._add_cron(
            "wpscan_batch",
            "Lote WPScan",
            self.settings.wpscan_cron,
            lambda: self.trigger_wpscan_batch(Trigger.SCHEDULE),
        )
        if self.settings.greenbone_enabled:
            self._add_cron(
                "greenbone_batch",
                "Lote Greenbone",
                self.settings.greenbone_cron,
                lambda: self.trigger_greenbone_batch(Trigger.SCHEDULE),
            )
        if self.settings.risk_enabled:
            self._add_cron(
                "risk_daily",
                "Prioridades (KEV/EPSS/exploits)",
                self.settings.risk_cron,
                lambda: self.trigger_risk(Trigger.SCHEDULE),
            )
        if self.settings.servers_enabled:
            self._add_cron(
                "servers_check",
                "Verificação dos servidores",
                self.settings.servers_cron,
                lambda: self.trigger_servers_check(Trigger.SCHEDULE),
            )
            if self.settings.patch_cron.strip():
                self._add_cron(
                    "patch_cycle",
                    "Ciclo de atualizações (anéis)",
                    self.settings.patch_cron,
                    lambda: self.start_patch_cycle(Trigger.SCHEDULE),
                )
            self.scheduler.add_job(
                self.advance_patch, "interval", minutes=10, id="patch_advance", name="Portões dos anéis"
            )
        self.scheduler.add_job(
            self.refresh_health,
            "interval",
            minutes=10,
            id="health",
            name="Saúde",
            next_run_time=datetime.now(self.scheduler.timezone),
        )
        self.scheduler.add_job(
            lambda: self.store.purge_older_than(self.settings.retention_days),
            CronTrigger(hour=4, minute=11, timezone=self.settings.timezone),
            id="purge",
            name="Limpeza",
        )
        self.scheduler.start()

    def _add_cron(self, job_id: str, name: str, expr: str, fn: Callable[[], Any]) -> None:
        try:
            trigger = CronTrigger.from_crontab(expr, timezone=self.settings.timezone)
        except ValueError as exc:
            self.schedule_errors[job_id] = f"expressão cron inválida '{expr}': {exc}"
            log.error(self.schedule_errors[job_id])
            return
        self.scheduler.add_job(
            fn, trigger, id=job_id, name=name, max_instances=1, coalesce=True, misfire_grace_time=3600
        )

    def shutdown(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
        for lane in self.lanes.values():
            lane.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------ filas
    def _submit(self, lane: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        def wrapper() -> None:
            with self._lock:
                self._busy[lane] += 1
            try:
                fn(*args, **kwargs)
            except Exception:
                log.exception("tarefa na fila %s falhou", lane)
            finally:
                with self._lock:
                    self._busy[lane] -= 1

        self.lanes[lane].submit(wrapper)

    def busy(self, lane: str) -> bool:
        with self._lock:
            return self._busy[lane] > 0

    # ------------------------------------------------------------------ ações
    def trigger_wpscan_batch(self, trigger: Trigger = Trigger.MANUAL) -> list[str]:
        run_ids = pipeline.plan_wpscan_batch(self.store, self.settings, trigger)
        self._submit("wpscan", pipeline.execute_wpscan_batch, self.store, self.settings, run_ids)
        return run_ids

    def trigger_greenbone_batch(
        self, trigger: Trigger = Trigger.MANUAL, host_ids: list[str] | None = None
    ) -> list[str]:
        run_ids = pipeline.plan_greenbone_batch(self.store, trigger, host_ids)
        if run_ids:
            self._submit("greenbone", pipeline.execute_greenbone_batch, self.store, self.settings, run_ids)
        return run_ids

    def run_host(self, host: Host, source: Source) -> Run | None:
        """Execução manual de um host. Devolve None se já houver uma ativa."""
        if source is Source.GREENBONE:
            ids = self.trigger_greenbone_batch(Trigger.MANUAL, [host.id])
            return self.store.get_run(ids[0]) if ids else None
        if source is Source.SERVER:
            ids = self.trigger_servers_check(Trigger.MANUAL, [host.id])
            return self.store.get_run(ids[0]) if ids else None
        run = pipeline.create_run(self.store, host, Source.WPSCAN, Trigger.MANUAL)
        if run:
            self._submit("wpscan", pipeline.execute_wpscan_batch, self.store, self.settings, [run.id])
        return run

    # ------------------------------------------------------------------ servidores
    def trigger_servers_check(self, trigger: Trigger = Trigger.MANUAL, host_ids: list[str] | None = None) -> list[str]:
        run_ids = servers_job.plan_checks(self.store, trigger, host_ids)
        for run_id in run_ids:
            self._submit("servers", servers_job.execute_check, self.store, self.settings, run_id)
        return run_ids

    def start_patch_cycle(self, trigger: Trigger = Trigger.MANUAL, actor: str = "agendamento") -> dict | None:
        cycle = patch_cycles.new_cycle(self.store, self.settings, trigger, actor)
        if cycle is not None:
            self.advance_patch()
        return cycle

    def advance_patch(self) -> None:
        def start(cycle_id: str, idx: int) -> None:
            cycle = self.store.get_cycle(cycle_id) or {}
            trig = Trigger(cycle.get("trigger", "schedule"))

            def ring_job() -> None:
                patch_cycles.run_ring(
                    self.store,
                    self.settings,
                    cycle_id,
                    idx,
                    lambda run_id: servers_job.execute_patch(self.store, self.settings, run_id),
                    trig,
                )
                self.advance_patch()  # o anel seguinte pode já poder começar (observação 0 h)

            self._submit("patch", ring_job)

        patch_cycles.advance(self.store, self.settings, start)

    def trigger_risk(self, trigger: Trigger = Trigger.MANUAL, *, download: bool = True) -> Run | None:
        run = create_risk_run(self.store, trigger)
        if run is not None:
            self._submit("risk", execute_risk, self.store, self.settings, run.id, download=download)
        return run

    def refresh_health(self) -> None:
        self._submit("misc", check_all, self.settings, self.store)

    def next_runs(self) -> list[dict[str, Any]]:
        out = []
        if not self.scheduler.running:
            return out
        for job in self.scheduler.get_jobs():
            out.append({"id": job.id, "name": job.name, "next": job.next_run_time})
        return sorted(out, key=lambda j: (j["next"] is None, j["next"] or datetime.max))
