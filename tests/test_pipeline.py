"""Pipelines com scanners e DefectDojo simulados: o que é importado, o que não é, e porquê."""

from __future__ import annotations

import json

import pytest

from vulnflux import pipeline
from vulnflux.collectors import wpscan
from vulnflux.collectors.wpscan import ScanOutput
from vulnflux.defectdojo import ImportResult
from vulnflux.errors import ErrorKind, VFError
from vulnflux.greenbone.lifecycle import LifecycleError, LifecycleResult, ServiceState
from vulnflux.greenbone.readiness import Check, Readiness, Status
from vulnflux.greenbone.scanner import ReportData
from vulnflux.models import Host, Run, RunStatus, Source, StepStatus, Trigger


class FakeDD:
    def __init__(self, fail: VFError | None = None, ping_fail: VFError | None = None):
        self.calls: list[dict] = []
        self.fail = fail
        self.ping_fail = ping_fail

    def ping(self):
        if self.ping_fail:
            raise self.ping_fail
        return {"latency_ms": 1, "products": 0}

    def reimport(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise self.fail
        return ImportResult(
            test_id=7, statistics={"delta": {"created": {"total": 2}, "closed": {"total": 0}}}, raw={"test_id": 7}
        )


@pytest.fixture
def host(store):
    return store.save_host(
        Host(name="www.exemplo.pt", url="https://www.exemplo.pt/", environment="PRD", greenbone_enabled=True)
    )


@pytest.fixture
def fake_wpscan(monkeypatch, wpscan_raw):
    state = {"raw": wpscan_raw, "code": 5}

    def run_scan(url, output, settings):
        if state["raw"] is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(state["raw"]))
        return ScanOutput(exit_code=state["code"], raw=state["raw"], stderr="")

    monkeypatch.setattr(wpscan, "run_scan", run_scan)
    monkeypatch.setattr(wpscan, "ensure_database", lambda settings: "BD atual")
    return state


def _new_run(store, host, source=Source.WPSCAN):
    return pipeline.create_run(store, host, source, Trigger.MANUAL)


# ------------------------------------------------------------------ WPScan


def test_wpscan_sucesso_importa_generic(store, settings, host, fake_wpscan):
    dd = FakeDD()
    run = pipeline.execute_wpscan(store, settings, _new_run(store, host).id, dd=dd)
    assert run.status is RunStatus.SUCCESS, run.error_message
    assert [s.name for s in run.steps] == ["Preparar", "Scan", "Validar", "Converter", "Gate", "Importar no DefectDojo"]
    assert all(s.status is StepStatus.OK for s in run.steps)
    call = dd.calls[0]
    assert call["scan_type"] == "Generic Findings Import" and call["test_title"] == "WPScan"
    assert call["product_name"] == "www.exemplo.pt" and call["product_type_name"] == "PRD"
    assert call["close_old_findings"] is True
    assert json.loads(call["content"])["findings"]
    assert run.stats["findings_total"] == 3 and run.stats["quota_remaining"] == 21
    assert run.stats["dd"] == {"test_id": 7, "created": 2, "closed": 0}
    assert set(run.artifacts) >= {"wpscan-raw.json", "defectdojo-generic.json", "defectdojo-response.json"}


def test_wpscan_resultado_invalido_nao_importa(store, settings, host, fake_wpscan):
    fake_wpscan["raw"] = {"target_url": "https://www.exemplo.pt/", "vuln_api": {"error": "API limit reached"}}
    dd = FakeDD()
    run = pipeline.execute_wpscan(store, settings, _new_run(store, host).id, dd=dd)
    assert run.status is RunStatus.FAILED and run.error_kind is ErrorKind.QUOTA
    assert dd.calls == []  # nada chega ao DefectDojo
    assert run.steps[-1].name == "Validar" and run.steps[-1].status is StepStatus.FAILED


def test_wpscan_sem_token_nem_corre(store, settings, host, fake_wpscan):
    s = settings.model_copy(update={"wpscan_api_token": type(settings.wpscan_api_token)("")})
    run = pipeline.execute_wpscan(store, s, _new_run(store, host).id, dd=FakeDD())
    assert run.status is RunStatus.FAILED and run.error_kind is ErrorKind.CONFIG and not run.steps


def test_wpscan_queda_abrupta_nao_fecha_antigos(store, settings, host, fake_wpscan):
    store.save_run(
        Run(
            host_id=host.id,
            host_name=host.name,
            source=Source.WPSCAN,
            status=RunStatus.SUCCESS,
            stats={"findings_total": 40},
        )
    )
    dd = FakeDD()
    run = pipeline.execute_wpscan(store, settings, _new_run(store, host).id, dd=dd)
    assert run.status is RunStatus.WARNING
    assert dd.calls[0]["close_old_findings"] is False
    assert "queda" in run.warnings[0]


def test_wpscan_falha_no_import_regista_detalhe(store, settings, host, fake_wpscan):
    dd = FakeDD(fail=VFError(ErrorKind.DATA, "DefectDojo rejeitou o ficheiro (400)", detail='{"file": ["x"]}'))
    run = pipeline.execute_wpscan(store, settings, _new_run(store, host).id, dd=dd)
    assert run.status is RunStatus.FAILED and run.error_kind is ErrorKind.DATA
    assert run.error_detail == '{"file": ["x"]}'
    assert run.steps[-1].name == "Importar no DefectDojo"


def test_nao_cria_execucao_duplicada(store, host):
    assert _new_run(store, host) is not None
    assert _new_run(store, host) is None


def test_selecao_roda_pelos_mais_antigos(store, settings):
    a = store.save_host(Host(name="a.pt", url="https://a.pt/"))
    b = store.save_host(Host(name="b.pt", url="https://b.pt/"))
    store.save_host(Host(name="c.pt", url="https://c.pt/"))
    store.save_host(Host(name="d.pt", url="https://d.pt/", enabled=False))
    store.save_host(Host(name="e.pt", wpscan_enabled=True, url=None, greenbone_enabled=True))
    store.save_run(Run(host_id=a.id, host_name="a.pt", source=Source.WPSCAN, status=RunStatus.SUCCESS))
    store.save_run(Run(host_id=b.id, host_name="b.pt", source=Source.WPSCAN, status=RunStatus.FAILED))
    names = [h.name for h in pipeline.select_wpscan_hosts(store, 3)]
    assert names == ["c.pt", "a.pt", "b.pt"]  # nunca analisado primeiro; depois por antiguidade


def test_lote_quota_baixa_ignora_sem_gastar(store, settings, host, fake_wpscan):
    ids = pipeline.plan_wpscan_batch(store, settings, Trigger.SCHEDULE)
    summary = pipeline.execute_wpscan_batch(
        store, settings, ids, dd=FakeDD(), quota_fn=lambda s: {"requests_remaining": 2}
    )
    assert summary["status"] == "ignorado"
    run = store.get_run(ids[0])
    assert run.status is RunStatus.SKIPPED and run.error_kind is ErrorKind.QUOTA


def test_lote_dd_em_baixo_ignora(store, settings, host, fake_wpscan):
    ids = pipeline.plan_wpscan_batch(store, settings, Trigger.SCHEDULE)
    dd = FakeDD(ping_fail=VFError(ErrorKind.DEPENDENCY, "DefectDojo inacessível"))
    pipeline.execute_wpscan_batch(store, settings, ids, dd=dd, quota_fn=lambda s: {"requests_remaining": 25})
    assert store.get_run(ids[0]).error_kind is ErrorKind.DEPENDENCY


def test_lote_para_quando_quota_esgota(store, settings, fake_wpscan):
    for n in "abc":
        store.save_host(Host(name=f"{n}.pt", url=f"https://{n}.pt/"))
    fake_wpscan["raw"]["vuln_api"]["requests_remaining"] = 3
    ids = pipeline.plan_wpscan_batch(store, settings, Trigger.SCHEDULE)
    summary = pipeline.execute_wpscan_batch(
        store, settings, ids, dd=FakeDD(), quota_fn=lambda s: {"requests_remaining": 25}
    )
    statuses = [store.get_run(i).status for i in ids]
    assert statuses == [RunStatus.SUCCESS, RunStatus.SKIPPED, RunStatus.SKIPPED]
    assert summary["status"] == "parcial"


# ------------------------------------------------------------------ Greenbone

REPORT = ReportData(
    xml=b"<report><report><results/></report></report>",
    scan_run_status="Done",
    results_total=12,
    by_threat={"High": 2, "Medium": 4, "Log": 6},
    hosts_scanned=1,
)


class FakeClient:
    def __init__(self, statuses, report=REPORT):
        self.statuses = list(statuses)
        self.report = report
        self.stopped = []

    def ensure_task(self, host):
        return "task-1"

    def start(self, task_id):
        return "report-1"

    def status(self, task_id):
        return (self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]), 50

    def fetch_report(self, report_id):
        return self.report

    def stop(self, task_id):
        self.stopped.append(task_id)


class FakeLifecycle:
    def __init__(self, fail=None):
        self.verbs = []
        self.fail = fail

    def run(self, verb):
        self.verbs.append(verb)
        if self.fail and verb != "stop":
            raise self.fail
        return LifecycleResult(action=verb, message="", services=[ServiceState("gvmd", "running", "", 0, "x")])


def ready(*a, **k):
    return Readiness(Status.READY)


def test_greenbone_lote_completo(store, settings, host):
    ids = pipeline.plan_greenbone_batch(store, Trigger.MANUAL)
    lc, dd = FakeLifecycle(), FakeDD()
    summary = pipeline.execute_greenbone_batch(
        store,
        settings,
        ids,
        client=FakeClient(["Running", "Done"]),
        lifecycle=lc,
        dd=dd,
        wait_fn=ready,
        sleep=lambda s: None,
    )
    run = store.get_run(ids[0])
    assert run.status is RunStatus.SUCCESS, run.error_message
    assert lc.verbs == ["update", "stop"]
    assert dd.calls[0]["scan_type"] == "OpenVAS Parser" and dd.calls[0]["test_title"] == "Greenbone"
    assert dd.calls[0]["filename"].endswith(".xml")  # o parser do DD escolhe pelo sufixo
    assert run.stats["by_severity"] == {"Critical": 0, "High": 2, "Medium": 4, "Low": 0, "Info": 6}
    assert summary["status"] == "concluído"


def test_greenbone_nao_pronto_ignora_e_desliga(store, settings, host):
    ids = pipeline.plan_greenbone_batch(store, Trigger.MANUAL)
    lc = FakeLifecycle()
    not_ready = Readiness(Status.NOT_READY, [Check("feed:NVT", False, "a sincronizar")])
    pipeline.execute_greenbone_batch(
        store,
        settings,
        ids,
        client=FakeClient(["Done"]),
        lifecycle=lc,
        dd=FakeDD(),
        wait_fn=lambda *a, **k: not_ready,
        sleep=lambda s: None,
    )
    run = store.get_run(ids[0])
    assert run.status is RunStatus.SKIPPED and run.error_kind is ErrorKind.DEPENDENCY
    assert "a sincronizar" in run.error_message
    assert lc.verbs == ["update", "stop"]  # mesmo sem scans, a stack volta a ser desligada


def test_greenbone_falha_a_ligar(store, settings, host):
    ids = pipeline.plan_greenbone_batch(store, Trigger.MANUAL)
    lc = FakeLifecycle(fail=LifecycleError("outra operação gb-ctl em curso", transient=True))
    pipeline.execute_greenbone_batch(
        store,
        settings,
        ids,
        client=FakeClient(["Done"]),
        lifecycle=lc,
        dd=FakeDD(),
        wait_fn=ready,
        sleep=lambda s: None,
    )
    assert store.get_run(ids[0]).error_kind is ErrorKind.TRANSIENT
    assert lc.verbs == ["update"]  # não liga → não tenta desligar


@pytest.mark.parametrize(
    "report,kind",
    [
        (ReportData(b"<r/>", "Interrupted", 3, {}, 1), ErrorKind.DATA),
        (ReportData(b"<r/>", "Done", 0, {}, 0), ErrorKind.DATA),
    ],
)
def test_greenbone_report_invalido_nao_importa(store, settings, host, report, kind):
    ids = pipeline.plan_greenbone_batch(store, Trigger.MANUAL)
    dd = FakeDD()
    pipeline.execute_greenbone_batch(
        store,
        settings,
        ids,
        client=FakeClient(["Done"], report),
        lifecycle=None,
        dd=dd,
        wait_fn=ready,
        sleep=lambda s: None,
    )
    run = store.get_run(ids[0])
    assert run.status is RunStatus.FAILED and run.error_kind is kind and dd.calls == []


def test_greenbone_task_interrompida(store, settings, host):
    ids = pipeline.plan_greenbone_batch(store, Trigger.MANUAL)
    dd = FakeDD()
    pipeline.execute_greenbone_batch(
        store,
        settings,
        ids,
        client=FakeClient(["Running", "Interrupted"]),
        lifecycle=None,
        dd=dd,
        wait_fn=ready,
        sleep=lambda s: None,
    )
    run = store.get_run(ids[0])
    assert run.status is RunStatus.FAILED and "Interrupted" in run.error_message and dd.calls == []


def test_greenbone_timeout_para_task(store, settings, host):
    ids = pipeline.plan_greenbone_batch(store, Trigger.MANUAL)
    s = settings.model_copy(update={"greenbone_scan_timeout_hours": 1})
    clock = iter(range(0, 100_000, 1000))
    client = FakeClient(["Running"])
    pipeline.execute_greenbone_batch(
        store,
        s,
        ids,
        client=client,
        lifecycle=None,
        dd=FakeDD(),
        wait_fn=ready,
        sleep=lambda x: None,
        clock=lambda: next(clock),
    )
    run = store.get_run(ids[0])
    assert run.status is RunStatus.FAILED and run.error_kind is ErrorKind.TRANSIENT
    assert client.stopped == ["task-1"]


def test_greenbone_desativado(store, settings, host):
    ids = pipeline.plan_greenbone_batch(store, Trigger.MANUAL)
    s = settings.model_copy(update={"greenbone_enabled": False})
    pipeline.execute_greenbone_batch(
        store, s, ids, client=FakeClient(["Done"]), lifecycle=None, dd=FakeDD(), wait_fn=ready, sleep=lambda x: None
    )
    assert store.get_run(ids[0]).error_kind is ErrorKind.CONFIG
