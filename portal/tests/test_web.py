from __future__ import annotations

import re

import pytest
import responses
from fastapi.testclient import TestClient
from pydantic import SecretStr

from socportal.monitor import Monitor
from socportal.web.app import create_app

from .conftest import soc_status


@pytest.fixture
def monitor(settings):
    with responses.RequestsMock() as rs:
        rs.get("http://vulnflux:8080/api/status", json=soc_status())
        rs.get("http://dd:8080/login", body="<p>Version 2.51.2 (x)</p>")
        rs.get("http://dd:8080/api/v2/products/", json={"count": 3})
        rs.get(
            "https://api.github.com/repos/DefectDojo/django-DefectDojo/releases/latest",
            json={"tag_name": "2.52.0", "published_at": "2026-10-27T00:00:00Z", "html_url": "https://x"},
        )
        rs.get("https://api.github.com/repos/ricardodomingues10/vuln-flux/releases/latest", status=404)
        m = Monitor(settings)
        m.run_once()
    return m


@pytest.fixture
def client(settings, monitor):
    app = create_app(settings, monitor, start=False)
    with TestClient(app) as c:
        yield c


def login(client):
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    r = client.post("/login", data={"username": "admin", "password": "pw-teste", "csrf_token": token, "next": "/"})
    assert r.status_code in (200, 303)
    # o login renova a sessão (e o token CSRF): lê o novo da página
    page = client.get("/")
    return re.search(r'name="csrf-token" content="([^"]+)"', page.text).group(1)


def test_exige_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/healthz").json()["status"] == "ok"


def test_password_errada(client):
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    r = client.post("/login", data={"username": "admin", "password": "x", "csrf_token": token})
    assert r.status_code == 401


def test_painel(client):
    login(client)
    r = client.get("/")
    assert r.status_code == 200
    html = r.text
    assert "Portal de teste" in html
    assert "desatualizado → 2.52.0" in html  # DefectDojo
    assert 'href="http://localhost:8081"' in html and 'rel="noopener noreferrer"' in html
    assert "sem interface web" in html  # Greenbone
    assert "Feed NVT" in html and "BD WPScan" in html  # listas
    assert 'class="edge edge-off"' in html  # VulnFlux→Greenbone adormecida
    assert "Content-Security-Policy" in r.headers
    board = client.get("/?partial=board")
    assert board.text.lstrip().startswith('<div id="board"')


def test_detalhe_do_servico(client):
    login(client)
    r = client.get("/s/vulnflux")
    assert r.status_code == 200
    assert "Lote WPScan" in r.text and "DefectDojo" in r.text
    assert client.get("/s/naoexiste").status_code == 404


def test_refresh_exige_csrf(client):
    token = login(client)
    assert client.post("/actions/refresh").status_code == 403
    assert client.post("/actions/refresh", headers={"X-CSRF-Token": token}).status_code == 204


def test_api_summary(client, settings):
    assert client.get("/api/summary").status_code == 401
    settings.api_token = SecretStr("api-123")
    assert client.get("/api/summary", headers={"Authorization": "Bearer errado"}).status_code == 401
    data = client.get("/api/summary", headers={"Authorization": "Bearer api-123"}).json()
    by_id = {s["id"]: s for s in data["services"]}
    assert by_id["defectdojo"]["outdated"] is True
    assert by_id["greenbone"]["status"] == "off"
    assert {f["id"] for f in data["freshness"]} == {"wpscan_db", "NVT"}
