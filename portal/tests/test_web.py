from __future__ import annotations

import re

import pytest
import responses
from fastapi.testclient import TestClient
from pydantic import SecretStr

from socportal import inventory
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


def test_inventario(client):
    login(client)
    r = client.get("/")
    assert r.status_code == 200
    html = r.text
    assert "serviços ativos" in html and 'data-node="vulnflux"' in html
    assert "liga-se a" in html and 'aria-label="Ligações de' in html  # as ligações também em texto
    assert 'class="mare' not in html  # os alertas vivem em /alertas and 'data-node="defectdojo"' in html
    assert "Saber" in html and "Gestão de vulnerabilidades" in html  # camada e função
    assert "data-edges='" in html and '"from": "vulnflux"' in html
    assert 'style="' not in html
    part = client.get("/?partial=inventory")
    assert part.text.lstrip().startswith('<div id="inventory"')
    d = client.get("/inventory/vulnflux")
    assert d.status_code == 200 and "Liga-se a" in d.text and "DefectDojo" in d.text and "Lote WPScan" in d.text
    assert "Greenbone" in client.get("/inventory/greenbone").text
    assert client.get("/inventory/nada").status_code == 404


def test_alertas_e_sino(client):
    login(client)
    home = client.get("/").text
    assert 'href="/alertas"' in home and "bell-count" in home  # há serviços em baixo/avisos no teste
    r = client.get("/alertas")
    assert r.status_code == 200 and 'class="mare' in r.text and "O que mudou" in r.text
    assert client.get("/alertas?partial=mare").text.lstrip().startswith("<section")


def test_painel(client):
    login(client)
    r = client.get("/estado")
    assert r.status_code == 200
    html = r.text
    assert "Portal de teste" in html
    assert "desatualizado → 2.52.0" in html  # DefectDojo
    assert 'href="http://localhost:8081"' in html and 'rel="noopener noreferrer"' in html
    assert "sem interface web" in html  # Greenbone
    assert "Feed NVT" in html and "BD WPScan" in html  # listas
    assert 'class="edge edge-off"' in html  # VulnFlux→Greenbone adormecida
    assert "Content-Security-Policy" in r.headers
    board = client.get("/estado?partial=board")
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


def test_ligacoes_ver_alterar_esconder_e_criar(client, monitor):
    token = login(client)
    h = {"X-CSRF-Token": token}
    home = client.get("/").text
    assert 'data-edge="vulnflux|defectdojo"' in home and "data-new-edge" in home

    painel = client.get("/ligacao?de=vulnflux&para=defectdojo").text
    assert "depende" in painel and "Alterar" in painel and 'name="via"' in painel

    r = client.post(
        "/ligacao",
        data={"de": "vulnflux", "para": "defectdojo", "via": "API REST v2", "what": "importa os findings"},
        headers=h,
    )
    assert r.status_code == 204
    edge = next(e for e in inventory.build(monitor)["edges"] if e["key"] == "vulnflux>defectdojo")
    assert edge["via"] == "API REST v2" and edge["what"] == "importa os findings" and edge["changed"]

    client.post("/ligacao", data={"de": "vulnflux", "para": "defectdojo", "acao": "remover"}, headers=h)
    inv = inventory.build(monitor)
    assert not any(e["key"] == "vulnflux>defectdojo" for e in inv["edges"])
    assert any(e["key"] == "vulnflux>defectdojo" for e in inv["hidden_edges"])
    assert "Mostrar outra vez" in client.get("/ligacao?de=vulnflux&para=defectdojo").text
    client.post("/ligacao", data={"de": "vulnflux", "para": "defectdojo", "acao": "repor"}, headers=h)
    edge = next(e for e in inventory.build(monitor)["edges"] if e["key"] == "vulnflux>defectdojo")
    assert edge["via"] == "depende de" and not edge["changed"]

    assert "Nova ligação" in client.get("/ligacao/nova?de=greenbone").text
    r = client.post(
        "/ligacao",
        data={"de": "greenbone", "para": "CMDB do cliente", "via": "ficheiro partilhado", "what": "lista de alvos"},
        headers=h,
    )
    assert r.status_code == 204
    inv = inventory.build(monitor)
    new = next(e for e in inv["edges"] if e["from"] == "greenbone" and e["kind"] == "acrescentada")
    assert inv["names"][new["to"]] == "CMDB do cliente"
    client.post("/ligacao", data={"de": "greenbone", "para": "CMDB do cliente", "acao": "remover"}, headers=h)
    assert not any(e["kind"] == "acrescentada" for e in inventory.build(monitor)["edges"])
    assert client.post("/ligacao", data={"de": "greenbone", "para": ""}, headers=h).status_code == 422


def test_css_com_impressao_digital(client):
    """O ?v= muda com o conteúdo do CSS/JS, para o browser não ficar com estilos antigos em cache."""
    from socportal.web.app import HERE, asset_version

    login(client)
    page = client.get("/").text
    v = asset_version(HERE / "static")
    assert len(v) == 12 and f"portal.css?v={v}" in page and f"app.js?v={v}" in page


def test_mapa_vista_posicoes_e_ligar(client, monitor):
    import json as _json

    token = login(client)
    h = {"X-CSRF-Token": token, "Content-Type": "application/json"}
    assert 'data-view="mapa"' in client.get("/").text and "map-canvas" not in client.get("/").text

    assert client.post("/layout", content=_json.dumps({"view": "mapa"}), headers=h).status_code == 204
    page = client.get("/").text
    assert "map-canvas" in page and 'data-port="vulnflux"' in page and 'data-x="' in page

    r = client.post(
        "/layout",
        content=_json.dumps(
            {
                "positions": {
                    "vulnflux": {"x": 812.4, "y": 33},
                    "../x": {"x": 1, "y": 1},
                    "greenbone": {"x": -50, "y": "nope"},
                }
            }
        ),
        headers=h,
    )
    assert r.status_code == 204
    saved = monitor.layout.read()["positions"]
    assert saved == {"vulnflux": {"x": 812, "y": 33}}
    assert 'data-node="vulnflux" data-x="812" data-y="33"' in client.get("/").text

    assert client.post("/layout", content=_json.dumps({"reset": True}), headers=h).status_code == 204
    assert monitor.layout.read()["positions"] == {}
    assert client.post("/layout", content=_json.dumps({"view": "xpto"}), headers=h).status_code == 400
    assert client.post("/layout", content="[]", headers=h).status_code == 400
    # sem CSRF não grava
    assert client.post(
        "/layout", content=_json.dumps({"view": "grelha"}), headers={"Content-Type": "application/json"}
    ).status_code in (400, 403)

    novo = client.get("/ligacao/nova?de=vulnflux&para=greenbone").text
    assert 'value="greenbone"' in novo
