from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import requests
import responses
from pydantic import SecretStr

from socportal.monitor import Monitor, evaluate_freshness

from .conftest import soc_status

LOGIN_HTML = "<p>Version 2.51.2 (abc)</p>"


def _mock_all(vf=None, dd_status=200):
    responses.get("http://vulnflux:8080/api/status", json=vf or soc_status())
    responses.get("http://dd:8080/login", body=LOGIN_HTML)
    responses.get("http://dd:8080/api/v2/products/", json={"count": 3}, status=dd_status)
    responses.get(
        "https://api.github.com/repos/DefectDojo/django-DefectDojo/releases/latest",
        json={"tag_name": "2.52.0", "published_at": "2026-10-27T00:00:00Z", "html_url": "https://x"},
    )
    responses.get("https://api.github.com/repos/ricardodomingues10/vuln-flux/releases/latest", status=404)


@responses.activate
def test_ciclo_completo(settings):
    _mock_all()
    m = Monitor(settings)
    m.run_once()
    assert m.state("vulnflux").status == "ok"
    assert m.state("defectdojo").status == "ok"
    assert m.state("defectdojo").version == "2.51.2"
    # Greenbone vem do componente reportado pelo VulnFlux
    assert m.state("greenbone").status == "off"
    assert m.state("greenbone").message == "parado (on-demand)"
    # versões
    dd = m.config.get("defectdojo")
    assert m.outdated(dd) is True
    assert m.outdated(m.config.get("vulnflux")) is None  # sem releases
    assert m.latest_for(m.config.get("vulnflux"))["error"] == "sem releases publicadas"
    # ligações: VulnFlux→DefectDojo diz ok, VulnFlux→Greenbone adormecida
    edges = {(e["from"], e["to"]): e["status"] for e in m.edges()}
    assert edges == {("vulnflux", "defectdojo"): "ok", ("vulnflux", "greenbone"): "off"}
    s = m.summary()
    assert s["counts"]["ok"] == 2 and s["counts"]["off"] == 1 and s["outdated"] == 1
    # persistido
    saved = json.loads((settings.data_dir / "state.json").read_text())
    assert saved["services"]["defectdojo"]["version"] == "2.51.2"


@responses.activate
def test_transicoes_geram_eventos_e_webhook(settings):
    settings.webhook_url = SecretStr("https://hooks.exemplo/abc")
    hook = responses.post("https://hooks.exemplo/abc", json={})
    _mock_all()
    m = Monitor(settings)
    m.run_once()
    assert list(m.events) == []  # primeira verificação ok não é notícia

    responses.replace(responses.GET, "http://dd:8080/api/v2/products/", body=requests.ConnectionError())
    m.run_once()
    # primeira falha: ainda por confirmar, sem evento nem alerta
    assert m.state("defectdojo").status == "ok" and m.state("defectdojo").pending == "fail"
    assert "a confirmar (1/2)" in m.state("defectdojo").message
    assert list(m.events) == [] and hook.call_count == 0
    m.run_once()
    assert m.state("defectdojo").status == "fail"
    assert m.events[0]["service"] == "defectdojo" and m.events[0]["to"] == "fail"
    assert hook.call_count == 1
    assert "EM BAIXO" in json.loads(hook.calls[0].request.body)["text"]

    responses.replace(responses.GET, "http://dd:8080/api/v2/products/", json={"count": 3})
    m.run_once()
    assert m.events[0]["to"] == "ok"
    assert "RECUPERADO" in json.loads(hook.calls[1].request.body)["text"]


@responses.activate
def test_falha_isolada_nao_alerta(settings):
    """Uma resposta lenta isolada (ex.: servidor ocupado) não pode gerar EM BAIXO + RECUPERADO."""
    settings.webhook_url = SecretStr("https://hooks.exemplo/abc")
    hook = responses.post("https://hooks.exemplo/abc", json={})
    _mock_all()
    m = Monitor(settings)
    m.run_once()
    responses.replace(responses.GET, "http://dd:8080/api/v2/products/", body=requests.ConnectionError())
    m.run_once()
    assert m._confirm_soon  # a confirmação é feita pouco depois, não no ciclo seguinte
    responses.replace(responses.GET, "http://dd:8080/api/v2/products/", json={"count": 3})
    m.run_once()
    assert m.state("defectdojo").status == "ok" and m.state("defectdojo").pending is None
    assert list(m.events) == [] and hook.call_count == 0


@responses.activate
def test_uma_so_confirmacao_alerta_logo(settings):
    settings.fail_confirmations = 1
    _mock_all()
    m = Monitor(settings)
    m.run_once()
    responses.replace(responses.GET, "http://dd:8080/api/v2/products/", body=requests.ConnectionError())
    m.run_once()
    assert m.state("defectdojo").status == "fail"


@responses.activate
def test_estado_sobrevive_ao_reinicio(settings):
    _mock_all()
    Monitor(settings).run_once()
    m2 = Monitor(settings)
    assert m2.state("defectdojo").status == "ok"
    assert m2.last_cycle is not None


@responses.activate
def test_vulnflux_em_baixo_deixa_greenbone_desconhecido(settings):
    responses.get("http://vulnflux:8080/api/status", body=requests.ConnectionError())
    responses.get("http://dd:8080/login", body=LOGIN_HTML)
    responses.get("http://dd:8080/api/v2/products/", json={"count": 3})
    responses.get("https://api.github.com/repos/DefectDojo/django-DefectDojo/releases/latest", status=403)
    responses.get("https://api.github.com/repos/ricardodomingues10/vuln-flux/releases/latest", status=403)
    m = Monitor(settings)
    m.run_once()
    assert m.state("vulnflux").status == "fail"
    assert m.state("greenbone").status == "unknown"
    assert m.state("defectdojo").status == "ok"  # uma queda não arrasta as outras
    assert "limite" in m.latest_for(m.config.get("defectdojo"))["error"]


def test_frescura():
    now = datetime(2026, 10, 29, 12, tzinfo=UTC)
    base = {"max_age_hours": 24}
    assert evaluate_freshness({**base, "updated_at": (now - timedelta(hours=5)).isoformat()}, now)["status"] == "ok"
    assert evaluate_freshness({**base, "updated_at": (now - timedelta(hours=30)).isoformat()}, now)["status"] == "warn"
    assert evaluate_freshness({**base, "updated_at": (now - timedelta(days=5)).isoformat()}, now)["status"] == "fail"
    off = evaluate_freshness({**base, "status": "off", "updated_at": (now - timedelta(days=5)).isoformat()}, now)
    assert off["status"] == "off" and off["age_hours"] == 120
    # o produtor sabe que o download de hoje falhou: pelo menos aviso
    failed = evaluate_freshness({**base, "status": "fail", "updated_at": (now - timedelta(hours=2)).isoformat()}, now)
    assert failed["status"] == "warn"
    assert evaluate_freshness({"id": "x"}, now)["status"] == "unknown"


@responses.activate
def test_config_alterada_e_relida(settings, config_file):
    _mock_all()
    m = Monitor(settings)
    m.run_once()
    text = config_file.read_text().replace("name: DefectDojo", "name: DefectDojo PRD")
    config_file.write_text(text)
    import os

    os.utime(config_file, (2, 2))
    m.run_once()
    assert m.config.get("defectdojo").name == "DefectDojo PRD"


def test_versoes_lentas_nao_atrasam_o_ciclo(settings, monkeypatch):
    """Em serviço, o ciclo não espera pelo GitHub (sem Internet cada consulta espera o tempo limite)."""
    m = Monitor(settings)
    called = []
    monkeypatch.setattr(m, "_refresh_versions", lambda cfg: called.append(1))
    monkeypatch.setattr(
        m.prober, "run", lambda *a, **k: __import__("socportal.probes", fromlist=["x"]).ProbeResult("ok", "ok")
    )
    m.run_once(versions=False)
    assert called == []
    m.run_once()
    assert called == [1]


@responses.activate
def test_sair_de_desligado_nao_espera_confirmacao(settings):
    """Ligar o primeiro servidor (desligado → atenção) é configuração, não oscilação: mostra logo."""
    from socportal.monitor import OFF, ServiceState

    _mock_all()
    m = Monitor(settings)
    m.run_once()
    m.states["defectdojo"] = ServiceState(id="defectdojo", status=OFF)
    responses.replace(responses.GET, "http://dd:8080/api/v2/products/", body=requests.ConnectionError())
    m.run_once()
    assert m.state("defectdojo").status == "fail" and m.state("defectdojo").pending is None
