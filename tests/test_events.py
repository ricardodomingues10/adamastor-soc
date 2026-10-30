from __future__ import annotations

import json
import socket

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from vulnflux import events
from vulnflux.engine import Engine
from vulnflux.models import Host, Run, Source
from vulnflux.web.app import create_app


def item(fid, host="www.a.pt", priority="P1", kev=False, cves=("CVE-2024-1",)):
    return {
        "finding_id": fid,
        "title": f"Vuln {fid}",
        "host": host,
        "severity": "High",
        "priority": priority,
        "score": 91,
        "cves": list(cves),
        "exploits": ["metasploit"],
        "kev": kev,
        "epss_percentile": 0.97,
        "planned": "2026-11-06",
        "reasons": ["KEV"],
    }


def lines(settings):
    f = settings.data_dir / "eventos" / "eventos.jsonl"
    return [json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []


def test_p1_e_kev_avisam_uma_vez(settings, store):
    sent = events.findings(store, settings, [item(1), item(2, priority="P2", kev=True), item(3, priority="P2")])
    assert sent == 2
    assert events.findings(store, settings, [item(1), item(2, priority="P2", kev=True)]) == 0  # já enviados
    evs = lines(settings)
    assert [e["vulnflux"]["finding_id"] for e in evs] == [1, 2]
    assert evs[0]["event"]["severity_name"] == "critical" and evs[0]["vulnerability"]["id"] == ["CVE-2024-1"]
    assert evs[0]["host"]["name"] == "www.a.pt" and evs[0]["event"]["provider"] == "adamastor-soc.vulnflux"
    # subir de P2 a P1 é uma situação nova
    assert events.findings(store, settings, [item(3)]) == 1


def test_avalanche_vira_resumo(settings, store):
    s = settings.model_copy(update={"events_max_per_run": 3})
    assert events.findings(store, s, [item(i, host=f"h{i % 2}") for i in range(10)]) == 1
    evs = lines(s)
    assert len(evs) == 1 and evs[0]["vulnflux"]["total"] == 10 and evs[0]["vulnflux"]["hosts"] == ["h0", "h1"]
    assert events.findings(store, s, [item(i) for i in range(10)]) == 0  # todos marcados como vistos


def test_desligado_nao_envia(settings, store):
    s = settings.model_copy(update={"events_enabled": False})
    assert events.findings(store, s, [item(1)]) == 0 and lines(s) == []


def test_syslog_udp_rfc5424(settings, store):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(5)
    s = settings.model_copy(update={"events_syslog": f"udp://127.0.0.1:{srv.getsockname()[1]}"})
    events.findings(store, s, [item(7, kev=True)])
    data = srv.recv(65535).decode()
    srv.close()
    head, body = data.split(" - vulnerabilidade - ", 1)
    assert head.startswith("<162>1 ")  # local4 (20) * 8 + crítico (2)
    assert json.loads(body)["vulnflux"]["kev"] is True
    assert lines(s)[0]["entrega"] == {"syslog": "ok"}


def test_destino_em_baixo_nao_falha(settings, store, monkeypatch):
    s = settings.model_copy(update={"events_webhook_url": SecretStr("http://127.0.0.1:9/hook")})
    assert events.findings(store, s, [item(1)]) == 1
    assert lines(s)[0]["entrega"]["webhook"].startswith("erro:")
    assert store.get_state("events")[0]["entrega"]["webhook"].startswith("erro:")


def test_webhook_texto(settings, store, monkeypatch):
    calls = []

    class R:
        def raise_for_status(self):
            return None

    monkeypatch.setattr(events.requests, "post", lambda url, json, timeout: calls.append(json) or R())
    s = settings.model_copy(update={"events_webhook_url": SecretStr("https://hooks.exemplo/x")})
    events.findings(store, s, [item(1, kev=True)])
    assert calls[0]["text"].startswith("🔴 Adamastor SOC · www.a.pt: Vuln 1 · KEV")


def test_servidor_avisa_na_transicao(settings, store):
    h = Host(name="srv1.lab", ssh_enabled=True)
    assert events.server(store, settings, h, "ok", "tudo em ordem") is False
    assert events.server(store, settings, h, "fail", "disco 97%") is True
    assert events.server(store, settings, h, "fail", "disco 97%") is False  # continua em falha: não repete
    assert events.server(store, settings, h, "unreachable", "timeout") is True
    assert events.server(store, settings, h, "ok", "") is False
    assert events.server(store, settings, h, "fail", "outra vez") is True


def test_falha_de_execucao(settings, store):
    from vulnflux.errors import ErrorKind, VFError
    from vulnflux.pipeline import RunRecorder

    run = Run(host_id="h", host_name="www.a.pt", source=Source.WPSCAN)
    store.save_run(run)
    RunRecorder(store, run, settings).fail(VFError(ErrorKind.DEPENDENCY, "WPScan API em baixo"))
    ev = lines(settings)[0]
    assert ev["event"]["type"] == ["execucao"] and "WPScan API em baixo" in ev["message"]


def test_exposicao_por_host(settings, store):
    events.save_exposure(store, [item(1), item(2, priority="P3"), item(3, host="b.pt", priority="P4", kev=True)], None)
    rows = store.get_state("exposure")["rows"]
    assert [(r["host"], r["prioridade"], r["kev"]) for r in rows] == [("www.a.pt", "P1", False), ("b.pt", "P4", True)]
    events.save_exposure(store, [], ["www.a.pt"])  # host corrigido: sai da lista, os outros ficam
    assert [r["host"] for r in store.get_state("exposure")["rows"]] == ["b.pt"]


@pytest.fixture
def client(settings, store, monkeypatch):
    eng = Engine(settings, store, start_scheduler=False)
    monkeypatch.setattr(eng, "_submit", lambda *a, **k: None)
    with TestClient(create_app(settings, store, eng, start_engine=False)) as c:
        yield c


def test_api_exposicao_e_eventos(client, settings, store):
    assert client.get("/api/exposure").status_code == 404
    settings.status_token = SecretStr("st-1")
    assert client.get("/api/exposure", headers={"Authorization": "Bearer x"}).status_code == 401
    events.save_exposure(store, [item(1, kev=True)], None)
    events.findings(store, settings, [item(1, kev=True)])
    auth = {"Authorization": "Bearer st-1"}
    body = client.get("/api/exposure", headers=auth).json()
    assert body["schema"] == "adamastor-exposure/1" and body["rows"][0]["cve"] == "CVE-2024-1"
    csv = client.get("/api/exposure?formato=csv", headers=auth).text.splitlines()
    assert csv[0].startswith("host,cve,prioridade,kev") and csv[1].startswith("www.a.pt,CVE-2024-1,P1,True")
    assert client.get("/api/events", headers=auth).json()["events"][0]["tipo"] == "vulnerabilidade"
