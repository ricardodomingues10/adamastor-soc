from __future__ import annotations

import copy
import shutil
from datetime import date
from pathlib import Path

import pytest
import requests
import responses

from vulnflux.errors import ErrorKind, VFError
from vulnflux.hosts import HostValidationError, host_from_form, parse_bulk
from vulnflux.models import Host, RunStatus, Trigger
from vulnflux.risk import feeds as feeds_mod
from vulnflux.risk.context import CRITICALITY, effective_criticality, normalize
from vulnflux.risk.enrich import enrich, finding_cves, risk_tags
from vulnflux.risk.feeds import FeedCache
from vulnflux.risk.job import create_risk_run, execute_risk
from vulnflux.risk.score import Intel, assess, merge_intel, remediation_date

RISK_FX = Path(__file__).parent / "fixtures" / "risk"


# ---------------------------------------------------------------------------- modelo


def test_exemplos_da_arquitetura():
    # Plugin WP com RCE: CVSS 9,8 · EPSS p0,97 · Metasploit · KEV · internet × alto
    a = assess(
        severity="Critical",
        cvss=9.8,
        has_cve=True,
        intel=Intel(epss_percentile=0.97, kev=True, exploits=frozenset({"metasploit"})),
        exposure="internet",
        criticality="alto",
        data_class="interno",
    )
    assert (a.score, a.priority) == (84, "P1")
    # XSS num site público: 6,1 · p0,92 · Nuclei · internet × médio
    b = assess(
        severity="Medium",
        cvss=6.1,
        has_cve=True,
        intel=Intel(epss_percentile=0.92, exploits=frozenset({"nuclei"})),
        exposure="internet",
        criticality="medio",
        data_class="interno",
    )
    assert (b.score, b.priority) == (44, "P3")
    # Mesmo CVSS 9,8 num servidor interno, sem exploit nem KEV
    c = assess(
        severity="Critical",
        cvss=9.8,
        has_cve=True,
        intel=Intel(epss_percentile=0.40),
        exposure="interno",
        criticality="medio",
        data_class="interno",
    )
    assert (c.score, c.priority) == (17, "P4")


def test_regras_kev():
    weak = Intel(epss_percentile=0.1, kev=True)
    internet = assess(
        severity="Low",
        cvss=3.0,
        has_cve=True,
        intel=weak,
        exposure="internet",
        criticality="baixo",
        data_class="publico",
    )
    assert internet.priority == "P1" and any("regra" in r for r in internet.reasons)
    dmz = assess(
        severity="Low", cvss=3.0, has_cve=True, intel=weak, exposure="dmz", criticality="baixo", data_class="publico"
    )
    assert dmz.priority == "P2"
    interno = assess(
        severity="Low",
        cvss=3.0,
        has_cve=True,
        intel=weak,
        exposure="interno",
        criticality="baixo",
        data_class="publico",
    )
    assert interno.priority == "P4"


def test_dados_sensiveis_elevam_criticidade():
    assert effective_criticality("medio", "sensiveis") == "critico"
    assert effective_criticality("baixo", "pessoais") == "alto"
    assert effective_criticality("critico", "pessoais") == "critico"
    a = assess(
        severity="High",
        cvss=None,
        has_cve=False,
        intel=Intel(),
        exposure="internet",
        criticality="medio",
        data_class="sensiveis",
    )
    assert a.context == 1.0 and a.priority == "P2"  # sem CVE: 0,65 × 1,0


def test_info_nao_e_priorizado_e_cvss_pela_severidade():
    assert (
        assess(
            severity="Info",
            cvss=None,
            has_cve=False,
            intel=Intel(),
            exposure="internet",
            criticality="alto",
            data_class="interno",
        )
        is None
    )
    a = assess(
        severity="High",
        cvss=None,
        has_cve=True,
        intel=Intel(),
        exposure="internet",
        criticality="critico",
        data_class="interno",
    )
    assert "pela severidade" in a.reasons[0] and a.score == round(100 * 0.3 * 0.75)


def test_ransomware_conta_como_exploit_maximo():
    a = assess(
        severity="High",
        cvss=7.0,
        has_cve=True,
        intel=Intel(kev=True, ransomware=True),
        exposure="interno",
        criticality="medio",
        data_class="interno",
    )
    assert a.exploit_level == 1.0


def test_merge_intel_pior_sinal():
    m = merge_intel(
        [
            Intel(epss=0.1, epss_percentile=0.5),
            Intel(epss=0.3, epss_percentile=0.9, kev=True, kev_date=date(2024, 1, 2), exploits=frozenset({"nuclei"})),
        ]
    )
    assert (m.epss, m.epss_percentile, m.kev, m.kev_date, m.exploits) == (
        0.3,
        0.9,
        True,
        date(2024, 1, 2),
        frozenset({"nuclei"}),
    )


def test_data_de_correcao():
    sla = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}
    assert remediation_date(date(2026, 10, 1), "P2", sla) == date(2026, 10, 31)
    # prazo da CISA antes do SLA ganha; prazo já passado antes da descoberta é ignorado
    assert remediation_date(date(2026, 10, 1), "P1", sla, kev_due=date(2026, 10, 3)) == date(2026, 10, 3)
    assert remediation_date(date(2026, 10, 1), "P1", sla, kev_due=date(2024, 1, 1)) == date(2026, 10, 8)


def test_sla_configuravel(settings):
    settings.risk_sla_days = "3, 15,x"
    assert settings.sla_days() == {"P1": 3, "P2": 15, "P3": 90, "P4": 180}


# ---------------------------------------------------------------------------- contexto no inventário


def test_normalizar_contexto():
    assert normalize("Crítico", CRITICALITY, "medio") == "critico"
    assert normalize("high", CRITICALITY, "medio") == "alto"
    assert normalize("", CRITICALITY, "medio") == "medio"
    with pytest.raises(ValueError, match="inválido"):
        normalize("enorme", CRITICALITY, "medio")


def test_formulario_e_lote_com_contexto():
    h = host_from_form(
        {
            "url": "https://a.exemplo.pt",
            "wpscan_enabled": "on",
            "criticality": "alto",
            "exposure": "dmz",
            "data_class": "pessoais",
        }
    )
    assert (h.criticality, h.exposure, h.data_class) == ("alto", "dmz", "pessoais")
    with pytest.raises(HostValidationError) as exc:
        host_from_form({"url": "https://a.exemplo.pt", "wpscan_enabled": "on", "exposure": "lua"})
    assert "exposure" in exc.value.errors
    # editar sem os campos (formulário antigo) mantém os valores
    h2 = host_from_form({"url": "https://a.exemplo.pt", "wpscan_enabled": "on"}, h)
    assert h2.criticality == "alto"
    res = parse_bulk(
        "www.b.exemplo.pt ; Lab ; avada ; crítico ; internet ; sensíveis\nwww.c.exemplo.pt",
        default_environment="PRD",
        wpscan=True,
        greenbone=False,
        existing_names=set(),
    )
    assert not res.errors
    assert (res.hosts[0].criticality, res.hosts[0].data_class) == ("critico", "sensiveis")
    assert (res.hosts[1].criticality, res.hosts[1].exposure) == ("medio", "internet")


# ---------------------------------------------------------------------------- feeds


def _file_urls(settings, base: Path = RISK_FX):
    settings.risk_kev_url = f"file://{base / 'kev.json'}"
    settings.risk_epss_url = f"file://{base / 'epss.csv.gz'}"
    settings.risk_exploitdb_url = f"file://{base / 'exploitdb.csv'}"
    settings.risk_metasploit_url = f"file://{base / 'metasploit.json'}"
    settings.risk_nuclei_url = f"file://{base / 'nuclei.json'}"


def test_feeds_locais_e_consulta(settings, store):
    _file_urls(settings)
    cache = FeedCache(settings, store)
    metas = cache.update_all()
    assert all(m.error is None for m in metas.values()), {k: m.error for k, m in metas.items()}
    assert metas["kev"].count == 2 and metas["kev"].source_date.startswith("2026-10-28")
    assert metas["epss"].source_date.startswith("2026-10-29")
    intel = cache.lookup(["cve-2023-39312", "CVE-2021-44228", "CVE-2020-0001", "CVE-1999-0001"])
    wp = intel["CVE-2023-39312"]
    assert wp.kev and not wp.ransomware and wp.epss == 0.9 and wp.exploits == {"metasploit", "exploitdb"}
    log4j = intel["CVE-2021-44228"]
    assert log4j.ransomware and log4j.exploits == {"metasploit", "exploitdb-verified", "nuclei"}
    assert intel["CVE-2020-0001"].exploits == {"nuclei"}  # módulo auxiliary do MSF não conta
    assert intel["CVE-1999-0001"] == Intel()
    # metadados visíveis no portal
    assert set(store.get_state("risk_feeds")) == {"kev", "epss", "exploitdb", "metasploit", "nuclei"}


@responses.activate
def test_epss_tenta_os_dias_anteriores(settings, store):
    settings.risk_epss_url = "https://epss.test/epss_scores-{date}.csv.gz"
    responses.get("https://epss.test/epss_scores-2026-10-29.csv.gz", status=404)
    responses.get("https://epss.test/epss_scores-2026-10-28.csv.gz", body=(RISK_FX / "epss.csv.gz").read_bytes())
    meta = FeedCache(settings, store).update("epss", settings.risk_epss_url, today=date(2026, 10, 29))
    assert meta.error is None and meta.count == 3


@responses.activate
def test_falha_mantem_a_copia_anterior(settings, store):
    _file_urls(settings)
    cache = FeedCache(settings, store)
    cache.update("kev", settings.risk_kev_url)
    responses.get("https://kev.test/kev.json", body=requests.ConnectionError())
    meta = cache.update("kev", "https://kev.test/kev.json")
    assert "inacessível" in meta.error and meta.count == 2  # contagem e data da cópia anterior
    assert cache.lookup(["CVE-2023-39312"])["CVE-2023-39312"].kev


def test_ficheiro_corrompido_nao_substitui(settings, store, tmp_path):
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "kev.json").write_text('{"nada": []}')
    _file_urls(settings)
    cache = FeedCache(settings, store)
    cache.update("kev", settings.risk_kev_url)
    meta = cache.update("kev", f"file://{bad / 'kev.json'}")
    assert "vulnerabilities" in meta.error
    assert cache.lookup(["CVE-2023-39312"])["CVE-2023-39312"].kev


def test_limite_de_tamanho(settings, store, monkeypatch, tmp_path):
    monkeypatch.setattr(feeds_mod, "MAX_DOWNLOAD", 10)
    with responses.RequestsMock() as rs:
        rs.get("https://grande.test/x", body="x" * 100)
        with pytest.raises(feeds_mod.FeedError, match="maior"):
            feeds_mod.fetch("https://grande.test/x", tmp_path / "x", settings)
    assert not (tmp_path / "x.part").exists()


# ---------------------------------------------------------------------------- DefectDojo


class FakeDD:
    """DefectDojo em memória: só o que o enriquecimento usa (paginate + patch)."""

    def __init__(self, products, findings):
        self.products = {p["id"]: p for p in products}
        self.findings = {f["id"]: f for f in findings}
        self.patches: list[tuple[str, dict]] = []

    def paginate(self, path, params=None, page_size=250):
        if path == "/products/":
            yield from copy.deepcopy(list(self.products.values()))
        elif path == "/findings/":
            pid = params["test__engagement__product"]
            yield from copy.deepcopy([f for f in self.findings.values() if f["product"] == pid and f["active"]])

    def patch(self, path, payload):
        self.patches.append((path, payload))
        kind, oid = path.strip("/").split("/")
        target = self.products if kind == "products" else self.findings
        target[int(oid)].update(payload)
        return target[int(oid)]


def _finding(fid, product, *, severity="High", cves=(), cvss=None, tags=(), date_="2026-10-20", **extra):
    return {
        "id": fid,
        "product": product,
        "active": True,
        "title": f"Finding {fid}",
        "severity": severity,
        "vulnerability_ids": [{"vulnerability_id": c} for c in cves],
        "cvssv3_score": cvss,
        "tags": list(tags),
        "date": date_,
        "epss_score": None,
        "epss_percentile": None,
        "known_exploited": False,
        "ransomware_used": False,
        "kev_date": None,
        "planned_remediation_date": None,
        **extra,
    }


@pytest.fixture
def cache(settings, store):
    _file_urls(settings)
    c = FeedCache(settings, store)
    c.update_all()
    return c


@pytest.fixture
def scenario():
    hosts = [
        Host(name="www.exemplo.pt", criticality="alto", exposure="internet"),
        Host(
            name="intranet.exemplo.pt",
            criticality="medio",
            exposure="interno",
            greenbone_enabled=True,
            wpscan_enabled=False,
        ),
        Host(name="novo.exemplo.pt"),
    ]
    dd = FakeDD(
        products=[
            {"id": 1, "name": "www.exemplo.pt", "business_criticality": None, "internet_accessible": False},
            {"id": 2, "name": "INTRANET.exemplo.pt", "business_criticality": "medium", "internet_accessible": False},
        ],
        findings=[
            _finding(10, 1, cves=["CVE-2023-39312"], cvss=7.5, tags=["wpscan", "plugin"]),
            _finding(11, 1, severity="Medium", tags=["wpscan", "risk:p1"]),  # tag antiga errada
            _finding(12, 1, severity="Info"),
            _finding(20, 2, severity="Critical", cves=["CVE-2020-0001"], cvss=9.8),
            _finding(21, 2, severity="High", cves=["CVE-2021-44228"], cvss=10.0, planned_remediation_date="2026-12-31"),
        ],
    )
    return hosts, dd


def test_enriquecimento(settings, cache, scenario):
    hosts, dd = scenario
    res = enrich(settings, dd, cache, hosts)
    assert res.products == 2 and res.products_missing == ["novo.exemplo.pt"]
    # products com o contexto do inventário
    assert dd.products[1]["business_criticality"] == "high" and dd.products[1]["internet_accessible"] is True
    assert res.products_updated == 1  # intranet já estava como medium/false

    wp = dd.findings[10]
    assert wp["tags"][:2] == ["wpscan", "plugin"]  # tags do scanner ficam
    assert {"risk:p1", "risk:kev", "risk:exploit-metasploit", "risk:exploit-exploitdb"} <= set(wp["tags"])
    assert wp["known_exploited"] is True and wp["kev_date"] == "2024-01-10"
    assert wp["epss_score"] == 0.9 and wp["epss_percentile"] == 0.97
    assert wp["planned_remediation_date"] == "2026-10-27"  # P1: 20/10 + 7 dias
    assert wp["severity"] == "High"  # nunca mexe na severidade

    assert dd.findings[11]["tags"] == ["wpscan", "risk:p3"]  # sem CVE: Medium × alto = 0,4×0,85
    assert "planned_remediation_date" not in [k for p, pl in dd.patches if p == "/findings/12/" for k in pl]
    assert dd.findings[12]["tags"] == []  # Info: ignorado

    log4j = dd.findings[21]
    assert log4j["ransomware_used"] is True
    assert log4j["planned_remediation_date"] == "2026-12-31"  # data posta à mão: respeitada
    assert res.manual_sla == 1

    assert res.by_priority["P1"] >= 1 and res.kev == 2
    assert res.top[0]["finding_id"] == 10


def test_segunda_passagem_nao_escreve_nada(settings, cache, scenario):
    hosts, dd = scenario
    enrich(settings, dd, cache, hosts)
    before = len(dd.patches)
    res = enrich(settings, dd, cache, hosts)
    assert res.updated == 0 and len(dd.patches) == before
    assert res.unchanged == res.findings


def test_prioridade_muda_e_a_nossa_data_acompanha(settings, cache, scenario):
    hosts, dd = scenario
    enrich(settings, dd, cache, hosts)
    assert dd.findings[10]["planned_remediation_date"] == "2026-10-27"
    hosts[0] = hosts[0].model_copy(update={"exposure": "isolado", "criticality": "baixo"})
    enrich(settings, dd, cache, hosts)
    f = dd.findings[10]
    assert "risk:p1" not in f["tags"]
    assert f["planned_remediation_date"] != "2026-10-27"  # era nossa: recalculada


def test_erros_de_escrita_param_ao_fim_de_varios(settings, cache, scenario, monkeypatch):
    hosts, dd = scenario

    def boom(path, payload):
        raise VFError(ErrorKind.DEPENDENCY, "DefectDojo respondeu 500")

    monkeypatch.setattr(dd, "patch", boom)
    monkeypatch.setattr("vulnflux.risk.enrich.MAX_CONSECUTIVE_ERRORS", 2)
    with pytest.raises(VFError, match="2x seguidas"):
        enrich(settings, dd, cache, hosts)


def test_cves_do_finding():
    assert finding_cves(
        {
            "vulnerability_ids": [{"vulnerability_id": "cve-2024-1234"}, {"vulnerability_id": "GHSA-x"}],
            "cve": "CVE-2024-1234",
        }
    ) == ["CVE-2024-1234"]
    assert risk_tags(None) == []


# ---------------------------------------------------------------------------- job


def test_job_regista_execucao_e_resumo(settings, store, scenario):
    hosts, dd = scenario
    store.save_hosts(hosts)
    _file_urls(settings)
    run = create_risk_run(store, Trigger.MANUAL)
    assert create_risk_run(store, Trigger.MANUAL) is None  # um de cada vez
    final = execute_risk(store, settings, run.id, dd=dd)
    assert final.status is RunStatus.WARNING  # novo.exemplo.pt ainda sem product
    assert [s.name for s in final.steps] == ["Atualizar feeds", "Calcular e escrever no DefectDojo"]
    assert final.stats["by_priority"]["P1"] >= 1
    summary = store.get_state("risk_summary")
    assert summary["top"][0]["host"] == "www.exemplo.pt"
    assert store.get_state("risk_last")["status"] == "warn"


def test_job_sem_feeds_falha_com_dependencia(settings, store, scenario):
    hosts, dd = scenario
    store.save_hosts(hosts)
    for name in ("kev", "epss", "exploitdb", "metasploit", "nuclei"):
        setattr(settings, f"risk_{name}_url", "")
    run = create_risk_run(store, Trigger.MANUAL)
    final = execute_risk(store, settings, run.id, dd=dd)
    assert final.status is RunStatus.FAILED and final.error_kind is ErrorKind.DEPENDENCY


def test_recalculo_apos_import(settings, store, scenario, cache):
    from vulnflux.risk.job import recalc_host

    hosts, dd = scenario
    detail = recalc_host(store, settings, hosts[0], dd)
    assert "P1 1" in detail
    summary = store.get_state("risk_summary")
    assert {t["host"] for t in summary["top"]} == {"www.exemplo.pt"}
    # depois o intranet: o resumo junta os dois
    recalc_host(store, settings, hosts[1], dd)
    assert {t["host"] for t in store.get_state("risk_summary")["top"]} == {"www.exemplo.pt", "intranet.exemplo.pt"}


def test_recalculo_sem_feeds_nao_faz_nada(settings, store, scenario, tmp_path):
    from vulnflux.risk.job import recalc_host

    hosts, dd = scenario
    shutil.rmtree(settings.data_dir / "risk", ignore_errors=True)
    assert recalc_host(store, settings, hosts[0], dd) is None
    assert dd.patches == []
