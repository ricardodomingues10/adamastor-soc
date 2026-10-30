"""Ligar com uma chave (deteção do produto), Automatismos e Mapa."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest
import responses
from fastapi.testclient import TestClient

from socportal import detect
from socportal.monitor import Monitor
from socportal.web.app import create_app

from .conftest import soc_status

VW = "https://cofre.exemplo.pt"


def _passthrough_404(rs: responses.RequestsMock, base: str) -> None:
    rs.add_callback(responses.GET, re.compile(re.escape(base) + r"/.*"), callback=lambda req: (404, {}, "not found"))


def test_normaliza_url():
    assert detect.normalize_url("cofre.exemplo.pt/") == "https://cofre.exemplo.pt"
    assert detect.normalize_url("http://x.lab:8080/app/") == "http://x.lab:8080/app"
    with pytest.raises(ValueError):
        detect.normalize_url("ftp://x")


def test_deteta_vaultwarden(settings):
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rs:
        rs.get(f"{VW}/alive", json="2026-10-30T00:00:00Z")
        rs.get(f"{VW}/api/config", json={"version": "2024.6.2", "server": {"name": "Vaultwarden", "url": "x"}})
        _passthrough_404(rs, VW)
        det = detect.detect(VW, settings)
    assert det.reachable and det.best.template == "vaultwarden" and det.best.confidence == "alta"
    assert any("/api/config" in e for e in det.best.evidence)


def test_deteta_grafana_e_defectdojo(settings):
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rs:
        rs.get("https://g.lab/api/health", json={"database": "ok", "version": "11.2.0"})
        _passthrough_404(rs, "https://g.lab")
        assert detect.detect("https://g.lab", settings).best.template == "grafana"
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rs:
        rs.get("https://dd.lab/login", body="<title>DefectDojo</title>")
        rs.get("https://dd.lab/api/v2/", status=401, headers={"WWW-Authenticate": "Token"})
        _passthrough_404(rs, "https://dd.lab")
        assert detect.detect("https://dd.lab", settings).best.template == "defectdojo"


def test_inacessivel(settings):
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rs:
        import requests

        rs.add_callback(
            responses.GET,
            re.compile(r"https://nada\.lab/.*"),
            callback=lambda req: (_ for _ in ()).throw(requests.ConnectionError("x")),
        )
        det = detect.detect("https://nada.lab", settings)
    assert not det.reachable and "sem resposta" in det.error


def test_valores_com_chave():
    v, secret = detect.build_values("defectdojo", "https://dd.lab", key="abc")
    assert v["link"] == "https://dd.lab" and secret == "abc" and v["_token_slot"] == 0
    assert v["probes"][0]["type"] == "defectdojo" and v["probes"][0]["auth_scheme"] == "Token"
    v, secret = detect.build_values("opensearch", "https://os.lab:9200", key="pw", user="leitor")
    assert secret == "leitor:pw" and v["probes"][0]["auth_scheme"] == "Basic" and v["api_url"] == "https://os.lab:9200"
    v, secret = detect.build_values("vaultwarden", VW)
    assert v["_token_slot"] is None and v["probes"][0]["url"] == "/alive"


# ---------------------------------------------------------------- páginas
@pytest.fixture
def monitor(settings):
    now = datetime.now(UTC)
    status = soc_status(
        jobs=[
            {
                "id": "wpscan_batch",
                "name": "Lote WPScan",
                "next_run": (now + timedelta(hours=5)).isoformat(),
                "last_status": "ok",
                "last_finished": (now - timedelta(hours=19)).isoformat(),
            },
            {
                "id": "servers_check",
                "name": "Verificação dos servidores",
                "next_run": (now + timedelta(days=2)).isoformat(),
                "last_status": "fail",
                "last_finished": (now - timedelta(hours=6)).isoformat(),
            },
        ]
    )
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rs:
        rs.get("http://vulnflux:8080/api/status", json=status)
        rs.get("http://dd:8080/login", body="<p>Version 2.51.2 (x)</p>")
        rs.get("http://dd:8080/api/v2/products/", json={"count": 3})
        rs.get(re.compile(r"https://api\.github\.com/.*"), status=404)
        m = Monitor(settings)
        m.run_once()
    return m


@pytest.fixture
def client(settings, monitor):
    with TestClient(create_app(settings, monitor, start=False)) as c:
        yield c


def _login(client):
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    client.post("/login", data={"username": "admin", "password": "pw-teste", "csrf_token": token, "next": "/"})
    return re.search(r'name="csrf-token" content="([^"]+)"', client.get("/").text).group(1)


def test_ligar_detecta_testa_e_grava(client, monitor):
    csrf = _login(client)
    assert "Descobrir e testar" in client.get("/connect").text
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rs:
        rs.get(f"{VW}/alive", json="2026-10-30T00:00:00Z")
        rs.get(f"{VW}/api/config", json={"version": "2024.6.2", "server": {"name": "Vaultwarden"}})
        _passthrough_404(rs, VW)
        r = client.post(
            "/connect/detect",
            data={"url": "cofre.exemplo.pt", "key": "segredo-123", "csrf_token": csrf},
            headers={"HX-Request": "true"},
        )
    assert r.status_code == 200 and "Vaultwarden" in r.text and "Guardar e ligar" in r.text
    assert "segredo-123" not in r.text  # a chave não volta ao browser
    ref = re.search(r'name="ref" value="([^"]+)"', r.text).group(1)
    r = client.post(
        "/connect/save",
        data={"template": "vaultwarden", "url": VW, "ref": ref, "name": "Cofre da equipa", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"].startswith("/s/cofre-da-equipa")
    svc = monitor.config.get("cofre-da-equipa")
    assert svc and svc.template == "vaultwarden" and svc.link == VW and svc.function == "secrets"


def test_ligar_com_chave_grava_segredo(client, monitor, settings):
    csrf = _login(client)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rs:
        rs.get("https://dd.lab/login", body="<title>DefectDojo</title><p>Version 2.52.1</p>")
        rs.get("https://dd.lab/api/v2/products/", json={"count": 1})
        _passthrough_404(rs, "https://dd.lab")
        r = client.post("/connect/detect", data={"url": "https://dd.lab", "key": "tok-dd", "csrf_token": csrf})
        assert "DefectDojo" in r.text
        ref = re.search(r'name="ref" value="([^"]+)"', r.text).group(1)
    r = client.post(
        "/connect/save",
        data={"template": "defectdojo", "url": "https://dd.lab", "ref": ref, "name": "", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    sid = r.headers["location"].split("/s/")[1].split("?")[0]
    svc = monitor.config.get(sid)
    assert svc.probes[0].type == "defectdojo" and svc.probes[0].token() == "tok-dd"
    assert sid != "defectdojo"  # o id já existia no portal.yaml: fica com sufixo


def test_automatismos(client):
    _login(client)
    page = client.get("/automations").text
    assert "Lote WPScan" in page and "Verificação dos servidores" in page and "Próximos 7 dias" in page
    assert page.count('class="tl-job') == 2 and "tl-fail" in page


def test_mapa(client):
    _login(client)
    page = client.get("/map").text
    for t in (
        "Ver",
        "Saber",
        "Decidir",
        "Responder",
        "Sustentar",
        "Gestão de vulnerabilidades",
        "por ligar",
        "VulnFlux",
    ):
        assert t in page, t
    assert 'style="' not in page
