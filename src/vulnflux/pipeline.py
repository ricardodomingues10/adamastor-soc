"""Execução das pipelines: cada execução (host × fonte) passa por passos registados.

    WPScan:     Preparar → Scan → Validar → Converter → Gate → Importar
    Greenbone:  Preparar task → Scan → Recolher report → Validar → Gate → Importar

Nada chega ao DefectDojo sem passar o "Validar". Cada passo fica gravado com início,
fim e detalhe, e uma falha guarda o tipo de erro e o detalhe técnico (stderr, corpo
da resposta), que é o que o dashboard mostra.
"""

from __future__ import annotations

import contextlib
import json
import logging
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import date
from typing import Any

from vulnflux.collectors import wpscan
from vulnflux.collectors.wpscan_tokens import TokenPool
from vulnflux.config import Settings
from vulnflux.converters.wpscan_generic import convert, severity_counts
from vulnflux.defectdojo import DefectDojo
from vulnflux.errors import ErrorKind, VFError
from vulnflux.gates import decide_close_old
from vulnflux.greenbone.lifecycle import GreenboneHost, LifecycleError
from vulnflux.greenbone.readiness import ReadinessConfig, wait_until_ready
from vulnflux.greenbone.scanner import DONE, FAILED_STATES, GreenboneClient, TaskBusy, threat_to_severity
from vulnflux.models import Host, Run, RunStatus, Source, Step, StepStatus, Trigger, utcnow
from vulnflux.store import JsonStore

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Registo de execuções
# ---------------------------------------------------------------------------


class RunRecorder:
    def __init__(self, store: JsonStore, run: Run, settings: Settings | None = None) -> None:
        self.store = store
        self.run = run
        self.settings = settings  # com settings, uma falha vira evento (alerta e SIEM)

    def save(self) -> None:
        self.store.save_run(self.run)

    def start(self) -> None:
        self.run.status = RunStatus.RUNNING
        self.run.started_at = utcnow()
        self.save()

    def begin_step(self, name: str, detail: str = "") -> Step:
        step = Step(name=name, status=StepStatus.RUNNING, started_at=utcnow(), detail=detail)
        self.run.steps.append(step)
        self.save()
        return step

    def end_step(self, step: Step, status: StepStatus = StepStatus.OK, detail: str | None = None) -> None:
        step.status = status
        step.finished_at = utcnow()
        if detail is not None:
            step.detail = detail
        self.save()

    @contextmanager
    def step(self, name: str) -> Iterator[Step]:
        step = self.begin_step(name)
        try:
            yield step
        except VFError as exc:
            self.end_step(step, StepStatus.FAILED, exc.message)
            raise
        except Exception as exc:
            self.end_step(step, StepStatus.FAILED, f"erro interno: {exc}")
            raise
        self.end_step(step)

    def artifact(self, name: str, data: bytes) -> None:
        self.store.write_artifact(self.run.id, name, data)
        if name not in self.run.artifacts:
            self.run.artifacts.append(name)

    def fail(self, exc: VFError, status: RunStatus = RunStatus.FAILED) -> None:
        for step in self.run.steps:
            if step.status is StepStatus.RUNNING:
                step.status = StepStatus.FAILED
                step.finished_at = utcnow()
        self.run.status = status
        self.run.error_kind = exc.kind
        self.run.error_message = exc.message
        self.run.error_detail = (exc.detail or None) and exc.detail[-4000:]
        self.run.finished_at = utcnow()
        if self.run.started_at is None:
            self.run.started_at = self.run.finished_at
        self.save()
        log.warning("execução %s (%s %s) falhou: %s", self.run.id, self.run.source.value, self.run.host_name, exc)
        if self.settings is not None and status is RunStatus.FAILED:
            from vulnflux import events

            try:
                events.run_failed(self.store, self.settings, self.run)
            except Exception:  # noqa: BLE001
                log.exception("evento de falha não registado")

    def finish_ok(self) -> None:
        self.run.status = RunStatus.WARNING if self.run.warnings else RunStatus.SUCCESS
        self.run.finished_at = utcnow()
        self.save()


def _internal(exc: Exception) -> VFError:
    log.exception("erro interno")
    return VFError(ErrorKind.PERMANENT, f"erro interno: {exc.__class__.__name__}: {exc}")


def create_run(store: JsonStore, host: Host, source: Source, trigger: Trigger) -> Run | None:
    """Cria uma execução em fila, exceto se já houver uma ativa para o mesmo host/fonte."""
    if store.active_run(host.id, source):
        return None
    return store.save_run(Run(host_id=host.id, host_name=host.name, source=source, trigger=trigger))


def skip_runs(store: JsonStore, run_ids: list[str], exc: VFError) -> None:
    for run_id in run_ids:
        run = store.get_run(run_id)
        if run and not run.status.finished:
            RunRecorder(store, run).fail(exc, status=RunStatus.SKIPPED)


def _product_type(host: Host, settings: Settings) -> str:
    return host.environment or settings.dd_default_product_type


def _previous_total(store: JsonStore, host: Host, source: Source) -> int | None:
    prev = store.last_run(host.id, source, good_only=True)
    return prev.findings_total if prev else None


def _gate_and_import(
    rec: RunRecorder,
    settings: Settings,
    dd: DefectDojo,
    host: Host,
    *,
    source: Source,
    content: bytes,
    filename: str,
    scan_type: str,
    test_title: str,
) -> None:
    run = rec.run
    with rec.step("Gate") as st:
        decision = decide_close_old(
            current_total=run.findings_total or 0,
            previous_total=_previous_total(rec.store, host, source),
            threshold=settings.gate_drop_threshold,
            min_previous=settings.gate_drop_min_previous,
        )
        run.stats["close_old_findings"] = decision.close_old_findings
        run.warnings.extend(decision.warnings)
        st.detail = (
            "fecha findings antigos" if decision.close_old_findings else "NÃO fecha findings antigos (queda abrupta)"
        )

    with rec.step("Importar no DefectDojo") as st:
        result = dd.reimport(
            content=content,
            filename=filename,
            scan_type=scan_type,
            test_title=test_title,
            product_name=host.name,
            product_type_name=_product_type(host, settings),
            close_old_findings=decision.close_old_findings,
            scan_date=date.today(),
        )
        rec.artifact("defectdojo-response.json", json.dumps(result.raw, indent=2, ensure_ascii=False).encode())
        delta = result.delta()
        run.stats["dd"] = {"test_id": result.test_id, **delta}
        parts = [f"test {result.test_id}"] + [f"{k} {v}" for k, v in delta.items()]
        st.detail = ", ".join(parts)

    _risk_step(rec, settings, dd, host)


def _risk_step(rec: RunRecorder, settings: Settings, dd: DefectDojo, host: Host) -> None:
    """Prioridades do host logo após o import. Falhar aqui é aviso, não falha do scan."""
    if not (settings.risk_enabled and settings.risk_after_import):
        return
    from vulnflux.risk.job import recalc_host

    step = rec.begin_step("Prioridades")
    try:
        detail = recalc_host(rec.store, settings, host, dd)
    except VFError as exc:
        rec.run.warnings.append(f"prioridades não recalculadas: {exc.message}")
        rec.end_step(step, StepStatus.FAILED, exc.message)
        return
    except Exception as exc:
        log.exception("recálculo de prioridades falhou")
        rec.run.warnings.append(f"prioridades não recalculadas: erro interno {exc.__class__.__name__}")
        rec.end_step(step, StepStatus.FAILED, str(exc)[:300])
        return
    if detail is None:
        rec.end_step(step, StepStatus.SKIPPED, "sem feeds em cache: fica para o job diário")
    else:
        rec.end_step(step, StepStatus.OK, detail)


# ---------------------------------------------------------------------------
# WPScan
# ---------------------------------------------------------------------------


def _scan_with_rotation(rec: RunRecorder, settings: Settings, pool: TokenPool, url: str) -> tuple[dict[str, Any], str]:
    """Scan + validação, repetindo com a chave seguinte quando uma esgota a quota.

    Devolve (JSON validado, fingerprint da chave usada). Um resultado obtido com uma
    chave esgotada é parcial e nunca segue para o import.
    """
    run = rec.run
    tried: set[str] = set()
    while True:
        choice = pool.choose(exclude=tried)
        if choice is None:
            n = len(pool)
            raise VFError(
                ErrorKind.QUOTA,
                "nenhuma chave WPScan com quota disponível"
                + (f" ({len(tried)} de {n} tentadas neste scan)" if tried else f" ({n} configuradas)"),
            )
        fp, token = choice
        tag = pool.label_of(fp)
        suffix = f" (chave {tag})" if len(pool) > 1 else ""

        with rec.step("Scan" + suffix) as st:
            output = rec.store.artifacts_dir / run.id / "wpscan-raw.json"
            scan = wpscan.run_scan(url, output, settings, token)
            if output.exists() and "wpscan-raw.json" not in run.artifacts:
                run.artifacts.append("wpscan-raw.json")
            if scan.stderr.strip():
                rec.artifact("wpscan-stderr.txt", scan.stderr.encode())
            st.detail = f"{url} — exit {scan.exit_code}"

        try:
            with rec.step("Validar" + suffix) as st:
                raw = wpscan.validate(scan, token_configured=True)
                quota = wpscan.quota_from_raw(raw)
                version = (raw.get("version") or {}).get("number") or "?"
                st.detail = f"WordPress {version}" + (f", quota restante {quota}" if quota is not None else "")
        except VFError as exc:
            if exc.kind is not ErrorKind.QUOTA:
                raise
            pool.mark_exhausted(fp, exc.message)
            tried.add(fp)
            run.warnings.append(f"chave {tag} esgotou durante o scan; repetido com outra chave")
            continue

        pool.record(fp, quota)
        run.stats["wpscan_key"] = tag
        if quota is not None:
            run.stats["quota_remaining"] = quota
        total = pool.total_remaining()
        if total is not None:
            run.stats["quota_total"] = total
        # As tentativas falhadas por quota não são avisos do resultado final.
        if run.warnings and all("esgotou durante o scan" in w for w in run.warnings):
            run.stats["key_retries"] = len(run.warnings)
            run.warnings.clear()
        return raw, fp


def execute_wpscan(
    store: JsonStore,
    settings: Settings,
    run_id: str,
    *,
    dd: DefectDojo | None = None,
    pool: TokenPool | None = None,
) -> Run | None:
    run = store.get_run(run_id)
    if run is None:
        return None
    rec = RunRecorder(store, run, settings)
    rec.start()
    try:
        host = store.get_host(run.host_id)
        if host is None:
            raise VFError(ErrorKind.PERMANENT, "o host foi removido")
        if not host.source_enabled(Source.WPSCAN):
            raise VFError(ErrorKind.CONFIG, "WPScan desativado para este host (ou sem URL)")
        if not settings.wpscan_tokens():
            # Sem chave o scan não tem dados de vulnerabilidades: importar fecharia tudo.
            raise VFError(ErrorKind.CONFIG, "nenhuma chave WPScan configurada (VF_WPSCAN_API_TOKENS)")
        dd = dd or DefectDojo(settings)
        pool = pool or TokenPool(settings, store)

        with rec.step("Preparar") as st:
            st.detail = wpscan.ensure_database(settings)

        raw, _fp = _scan_with_rotation(rec, settings, pool, host.url or "")

        with rec.step("Converter") as st:
            generic = convert(
                raw,
                include_interesting=settings.wpscan_include_interesting,
                include_users=settings.wpscan_include_users,
            )
            counts = severity_counts(generic)
            run.stats["findings_total"] = len(generic["findings"])
            run.stats["by_severity"] = counts
            rec.artifact("defectdojo-generic.json", json.dumps(generic, indent=2, ensure_ascii=False).encode())
            st.detail = f"{len(generic['findings'])} findings"

        _gate_and_import(
            rec,
            settings,
            dd,
            host,
            source=Source.WPSCAN,
            content=json.dumps(generic).encode(),
            filename="wpscan-generic.json",
            scan_type="Generic Findings Import",
            test_title="WPScan",
        )
        rec.finish_ok()
    except VFError as exc:
        rec.fail(exc)
    except Exception as exc:
        rec.fail(_internal(exc))
    return rec.run


def select_wpscan_hosts(store: JsonStore, limit: int) -> list[Host]:
    """Rotação sem estado: primeiro os nunca analisados, depois a tentativa mais antiga."""
    latest = store.latest_matrix()
    candidates = [h for h in store.list_hosts() if h.source_enabled(Source.WPSCAN)]

    def key(host: Host) -> tuple[int, str]:
        run = latest.get((host.id, Source.WPSCAN))
        if run is None:
            return (0, "")
        return (1, run.created_at.isoformat())

    candidates = [h for h in candidates if not store.active_run(h.id, Source.WPSCAN)]
    return sorted(candidates, key=key)[:limit]


def plan_wpscan_batch(store: JsonStore, settings: Settings, trigger: Trigger) -> list[str]:
    run_ids = []
    for host in select_wpscan_hosts(store, settings.wpscan_batch_size):
        run = create_run(store, host, Source.WPSCAN, trigger)
        if run:
            run_ids.append(run.id)
    return run_ids


def execute_wpscan_batch(
    store: JsonStore,
    settings: Settings,
    run_ids: list[str],
    *,
    dd: DefectDojo | None = None,
    pool: TokenPool | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {"started_at": utcnow(), "runs": len(run_ids), "status": "a correr"}
    store.set_state("batch_wpscan", summary)

    def finish(status: str, message: str = "") -> dict[str, Any]:
        summary.update(status=status, message=message, finished_at=utcnow())
        counts: dict[str, int] = {}
        for rid in run_ids:
            r = store.get_run(rid)
            if r:
                counts[r.status.value] = counts.get(r.status.value, 0) + 1
        summary["counts"] = counts
        if pool is not None:
            summary["quota_end"] = pool.total_remaining()
        store.set_state("batch_wpscan", summary)
        return summary

    if not run_ids:
        return finish("vazio", "nenhum host elegível")

    # Pré-verificações: falhar aqui custa zero pedidos à API do WPScan.
    try:
        if not settings.wpscan_tokens():
            raise VFError(ErrorKind.CONFIG, "nenhuma chave WPScan configurada (VF_WPSCAN_API_TOKENS)")
        dd = dd or DefectDojo(settings)
        dd.ping()
        pool = pool or TokenPool(settings, store)
        pool.refresh()
        summary["keys"] = len(pool)
        summary["quota_start"] = pool.total_remaining()
        if pool.all_unreachable():
            # Sem a API não há dados de vulnerabilidades: não vale a pena gastar tempo a analisar.
            raise VFError(ErrorKind.DEPENDENCY, "API do WPScan inacessível para todas as chaves")
        if not pool.usable():
            raise VFError(
                ErrorKind.QUOTA,
                f"nenhuma das {len(pool)} chaves WPScan tem quota acima de {settings.wpscan_min_quota}",
            )
        wpscan.ensure_database(settings)
    except VFError as exc:
        skip_runs(store, run_ids, exc)
        return finish("ignorado", exc.message)
    except Exception as exc:
        skip_runs(store, run_ids, _internal(exc))
        return finish("erro", str(exc))

    for index, run_id in enumerate(run_ids):
        execute_wpscan(store, settings, run_id, dd=dd, pool=pool)
        if index + 1 < len(run_ids) and not pool.usable():
            skip_runs(
                store,
                run_ids[index + 1 :],
                VFError(ErrorKind.QUOTA, f"todas as {len(pool)} chaves WPScan esgotaram durante o lote"),
            )
            return finish("parcial", "quota esgotada a meio do lote")
    return finish("concluído")


# ---------------------------------------------------------------------------
# Greenbone
# ---------------------------------------------------------------------------


def plan_greenbone_batch(
    store: JsonStore,
    trigger: Trigger,
    host_ids: list[str] | None = None,
) -> list[str]:
    hosts = store.list_hosts()
    if host_ids is not None:
        wanted = set(host_ids)
        hosts = [h for h in hosts if h.id in wanted]
    run_ids = []
    for host in hosts:
        if host.source_enabled(Source.GREENBONE):
            run = create_run(store, host, Source.GREENBONE, trigger)
            if run:
                run_ids.append(run.id)
    return run_ids


def readiness_config(settings: Settings) -> ReadinessConfig:
    return ReadinessConfig(
        socket_path=settings.greenbone_socket,
        username=settings.greenbone_user,
        password=settings.greenbone_password.get_secret_value(),
        scanner_id=settings.greenbone_scanner_id,
        scan_config_id=settings.greenbone_scan_config_id,
        min_nvts=settings.greenbone_min_nvts,
        max_feed_age_days=settings.greenbone_max_feed_age_days,
        block_on_stale_feed=settings.greenbone_block_on_stale_feed,
    )


def lifecycle_host(settings: Settings) -> GreenboneHost | None:
    if not settings.greenbone_lifecycle_enabled:
        return None
    return GreenboneHost(
        host=settings.greenbone_ssh_host,
        user=settings.greenbone_ssh_user,
        identity_file=settings.greenbone_ssh_key,
        known_hosts=settings.greenbone_ssh_known_hosts,
        port=settings.greenbone_ssh_port,
    )


class _Active:
    def __init__(self, rec: RunRecorder, host: Host, task_id: str, report_id: str, step: Step, started: float):
        self.rec, self.host, self.task_id, self.report_id = rec, host, task_id, report_id
        self.step, self.started = step, started
        self.last_status = ""
        self.poll_errors = 0


def _process_report(
    rec: RunRecorder, settings: Settings, client: GreenboneClient, dd: DefectDojo, active: _Active
) -> None:
    run = rec.run
    with rec.step("Recolher report") as st:
        data = client.fetch_report(active.report_id)
        rec.artifact("greenbone-report.xml", data.xml)
        st.detail = f"{data.results_total} resultados, {data.hosts_scanned} host(s)"

    with rec.step("Validar") as st:
        if data.scan_run_status and data.scan_run_status != DONE:
            raise VFError(ErrorKind.DATA, f"report com estado '{data.scan_run_status}', não 'Done'")
        if data.hosts_scanned == 0 and data.results_total == 0:
            # Alvo inacessível (alive test falhou): importar fecharia todos os findings.
            raise VFError(ErrorKind.DATA, "nenhum host analisado: alvo inacessível ou alive test falhou")
        run.stats["findings_total"] = data.results_total
        run.stats["by_severity"] = threat_to_severity(data.by_threat)
        if data.ports is not None:
            run.stats["ports_detected"] = data.ports
        if data.results:
            run.stats["results"] = data.results[:40]
        if data.top:
            run.stats["top"] = data.top
            run.stats["cvss9"] = sum(1 for t in data.top if t["cvss"] >= 9.0)
        st.detail = "report completo"

    _gate_and_import(
        rec,
        settings,
        dd,
        active.host,
        source=Source.GREENBONE,
        content=data.xml,
        filename="greenbone-report.xml",
        scan_type="OpenVAS Parser",
        test_title="Greenbone",
    )
    rec.finish_ok()


def _discovery_step(rec: RunRecorder, settings: Settings, host: Host) -> str | None:
    """Perfil "descoberta": nmap pela sonda → port list do host. Se falhar, o scan segue no perfil rápido."""
    from vulnflux.greenbone import discovery
    from vulnflux.greenbone.scanner import profile_of

    if profile_of(host, settings) != "descoberta":
        return None
    run = rec.run
    step = rec.begin_step("Descobrir portas")
    if not discovery.enabled(settings):
        run.warnings.append(
            "perfil descoberta sem sonda configurada (VF_GREENBONE_DISCOVERY_URL): usado o perfil rápido"
        )
        rec.end_step(step, StepStatus.SKIPPED, "sonda não configurada: perfil rápido")
        return None
    try:
        found = discovery.discover(settings, host.greenbone_target)
    except VFError as exc:
        run.warnings.append(f"descoberta de portas falhou ({exc.message}): usado o perfil rápido")
        rec.end_step(step, StepStatus.FAILED, exc.message)
        return None
    run.stats["discovery"] = {
        "tcp": found.tcp[:300],
        "count": len(found.tcp),
        "seconds": found.seconds,
        "nmap": found.nmap,
    }
    if not found.tcp:
        run.warnings.append("a sonda não encontrou portas TCP abertas: o Greenbone testa só as UDP comuns")
    shown = ", ".join(str(p) for p in found.tcp[:20]) + ("…" if len(found.tcp) > 20 else "")
    rec.end_step(
        step, StepStatus.OK, f"{len(found.tcp)} portas TCP abertas em {found.seconds:.0f}s: {shown or 'nenhuma'}"
    )
    return found.port_spec(settings.greenbone_discovery_udp)


def _set_gb_state(store: JsonStore, **fields: Any) -> None:
    state = store.get_state("greenbone", {}) or {}
    state.update(fields, updated_at=utcnow())
    store.set_state("greenbone", state)


def execute_greenbone_batch(
    store: JsonStore,
    settings: Settings,
    run_ids: list[str],
    *,
    client: GreenboneClient | None = None,
    lifecycle: GreenboneHost | None | bool = True,
    dd: DefectDojo | None = None,
    wait_fn: Callable[..., Any] = wait_until_ready,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    summary: dict[str, Any] = {"started_at": utcnow(), "runs": len(run_ids), "status": "a correr"}
    store.set_state("batch_greenbone", summary)
    lc = lifecycle_host(settings) if lifecycle is True else (lifecycle or None)
    client = client or GreenboneClient(settings)
    stack_started = False

    def finish(status: str, message: str = "") -> dict[str, Any]:
        summary.update(status=status, message=message, finished_at=utcnow())
        counts: dict[str, int] = {}
        for rid in run_ids:
            r = store.get_run(rid)
            if r:
                counts[r.status.value] = counts.get(r.status.value, 0) + 1
        summary["counts"] = counts
        store.set_state("batch_greenbone", summary)
        return summary

    if not run_ids:
        return finish("vazio", "nenhum host com Greenbone ativo")

    try:
        if not settings.greenbone_enabled:
            raise VFError(ErrorKind.CONFIG, "Greenbone desativado (VF_GREENBONE_ENABLED=false)")
        dd = dd or DefectDojo(settings)
        dd.ping()

        if lc is not None:
            verb = "update" if settings.greenbone_update_before_scan else "start"
            _set_gb_state(store, phase=f"a executar gb-ctl {verb}")
            try:
                result = lc.run(verb)
            except LifecycleError as exc:
                kind = ErrorKind.TRANSIENT if exc.transient else ErrorKind.CONFIG
                raise VFError(kind, f"não foi possível ligar o Greenbone: {exc}") from exc
            stack_started = True
            _set_gb_state(
                store, phase="a aguardar prontidão", lifecycle={"action": verb, "running": sorted(result.running())}
            )

        _set_gb_state(store, phase="a aguardar prontidão")
        readiness = wait_fn(readiness_config(settings), timeout_s=settings.greenbone_ready_timeout_hours * 3600)
        _set_gb_state(store, readiness=readiness.to_dict())
        from vulnflux.health import record_greenbone_feeds

        record_greenbone_feeds(store, readiness)
        if not readiness.ready:
            kind = ErrorKind.CONFIG if readiness.status.value == "failed" else ErrorKind.DEPENDENCY
            raise VFError(kind, f"Greenbone não ficou pronto: {readiness.summary()}")
    except VFError as exc:
        skip_runs(store, run_ids, exc)
        _shutdown(store, settings, lc, stack_started)
        _set_gb_state(store, phase="parado" if stack_started else "erro antes do arranque")
        return finish("ignorado", exc.message)
    except Exception as exc:
        skip_runs(store, run_ids, _internal(exc))
        _shutdown(store, settings, lc, stack_started)
        return finish("erro", str(exc))

    _set_gb_state(store, phase="a analisar")
    queue = list(run_ids)
    active: dict[str, _Active] = {}
    timeout_s = settings.greenbone_scan_timeout_hours * 3600
    try:
        while queue or active:
            while queue and len(active) < max(1, settings.greenbone_concurrency):
                run = store.get_run(queue.pop(0))
                if run is None or run.status.finished:
                    continue
                rec = RunRecorder(store, run, settings)
                rec.start()
                try:
                    host = store.get_host(run.host_id)
                    if host is None or not host.source_enabled(Source.GREENBONE):
                        raise VFError(ErrorKind.CONFIG, "host removido ou Greenbone desativado")
                    adopted: str | None = None
                    port_spec = _discovery_step(rec, settings, host)
                    with rec.step("Preparar task") as st:
                        try:
                            task_id = client.ensure_task(host, port_spec) if port_spec else client.ensure_task(host)
                            profile = getattr(client, "last_profile", "") or "completo"
                            run.stats["gb_profile"] = profile
                            run.warnings.extend(getattr(client, "notes", []) or [])
                            st.detail = f"task {task_id} → {host.greenbone_target} · perfil {profile}"
                        except TaskBusy as busy:
                            if not busy.report_id:
                                raise
                            # Scan lançado por uma execução anterior (ex.: VulnFlux reiniciado a meio):
                            # continua no gvmd, por isso acompanha-se esse em vez de lançar outro.
                            task_id, adopted = busy.task_id, busy.report_id
                            st.detail = (
                                f"task {task_id} já estava a correr ({busy.status}): "
                                f"o VulnFlux retoma o scan em curso (report {adopted})"
                            )
                    step = rec.begin_step("Scan", "a retomar scan em curso" if adopted else "a iniciar")
                    report_id = adopted or client.start(task_id)
                    run.stats["greenbone"] = {"task_id": task_id, "report_id": report_id, "adopted": bool(adopted)}
                    rec.save()
                    active[run.id] = _Active(rec, host, task_id, report_id, step, clock())
                except VFError as exc:
                    rec.fail(exc)
                except Exception as exc:
                    rec.fail(_internal(exc))

            if not active:
                continue
            sleep(settings.greenbone_poll_seconds)

            for run_id in list(active):
                a = active[run_id]
                try:
                    status, progress = client.status(a.task_id)
                    a.poll_errors = 0
                except VFError as exc:
                    a.poll_errors += 1
                    if a.poll_errors >= 10:
                        a.rec.fail(
                            VFError(ErrorKind.DEPENDENCY, f"sem estado da task após 10 tentativas: {exc.message}")
                        )
                        del active[run_id]
                    continue

                label = f"{status} {progress}%"
                if label != a.last_status:
                    a.step.detail = label
                    a.rec.save()
                    a.last_status = label

                if status == DONE:
                    a.rec.end_step(a.step, StepStatus.OK, "Done 100%")
                    del active[run_id]
                    try:
                        _process_report(a.rec, settings, client, dd, a)
                    except VFError as exc:
                        a.rec.fail(exc)
                    except Exception as exc:
                        a.rec.fail(_internal(exc))
                elif status in FAILED_STATES:
                    del active[run_id]
                    a.rec.fail(VFError(ErrorKind.DATA, f"scan terminou com estado '{status}': nada importado"))
                elif clock() - a.started > timeout_s:
                    del active[run_id]
                    with contextlib.suppress(VFError):
                        client.stop(a.task_id)
                    a.rec.fail(
                        VFError(
                            ErrorKind.TRANSIENT,
                            f"scan excedeu {settings.greenbone_scan_timeout_hours:g} h e foi parado: nada importado",
                        )
                    )
    finally:
        _shutdown(store, settings, lc, stack_started)

    return finish("concluído")


def _shutdown(store: JsonStore, settings: Settings, lc: GreenboneHost | None, stack_started: bool) -> None:
    if lc is None or not stack_started or not settings.greenbone_stop_after:
        _set_gb_state(store, phase="sempre ligado" if lc is None else "ligado")
        return
    try:
        lc.run("stop")
        _set_gb_state(store, phase="parado", lifecycle={"action": "stop", "at": utcnow()})
    except LifecycleError as exc:
        log.error("falha a parar o Greenbone: %s", exc)
        _set_gb_state(store, phase="erro ao parar", lifecycle={"action": "stop", "error": str(exc)})
