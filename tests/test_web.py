from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from vulnflux.engine import Engine
from vulnflux.models import Host, Run, RunStatus, Source
from vulnflux.web.app import create_app


@pytest.fixture
def engine(settings, store, monkeypatch):
    eng = Engine(settings, store, start_scheduler=False)
    submitted = []
    monkeypatch.setattr(eng, "_submit", lambda lane, fn, *a, **k: submitted.append((lane, fn.__name__)))
    eng.submitted = submitted
    return eng


@pytest.fixture
def client(settings, store, engine):
    app = create_app(settings, store, engine, start_engine=False)
    with TestClient(app) as c:
        yield c


def csrf_of(client: TestClient, path: str = "/login") -> str:
    html = client.get(path).text
    m = re.search(r'name="csrf-token" content="([^"]+)"', html) or re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "token CSRF não encontrado"
    return m.group(1)


def login(client: TestClient, password: str = "segredo-de-teste"):  # noqa: S107
    token = csrf_of(client)
    return client.post(
        "/login",
        data={"username": "admin", "password": password, "csrf_token": token, "next": "/hosts"},
        follow_redirects=False,
    )


@pytest.fixture
def auth(client):
    assert login(client).status_code == 303
    token = csrf_of(client, "/")
    return {"X-CSRF-Token": token, "HX-Request": "true"}


def test_paginas_exigem_login(client):
    for path in ["/", "/hosts", "/runs", "/errors", "/settings"]:
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login")
    r = client.get("/hosts", headers={"HX-Request": "true"}, follow_redirects=False)
    assert r.status_code == 401 and r.headers["HX-Redirect"].startswith("/login")
    assert client.get("/healthz").json()["status"] == "ok"


def test_login(client):
    assert login(client, "errada").status_code == 401
    r = login(client)
    assert r.status_code == 303 and r.headers["location"] == "/hosts"
    assert client.get("/").status_code == 200


def test_login_sem_csrf_recusado(client):
    client.get("/login")
    r = client.post("/login", data={"username": "admin", "password": "segredo-de-teste"})
    assert r.status_code == 403


def test_login_bloqueia_apos_varias_falhas(client):
    for _ in range(8):
        login(client, "errada")
    assert login(client).status_code == 429


def test_open_redirect_bloqueado(client):
    token = csrf_of(client)
    r = client.post(
        "/login",
        data={"username": "admin", "password": "segredo-de-teste", "csrf_token": token, "next": "//evil.example"},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/"


def test_cabecalhos_de_seguranca(client):
    r = client.get("/login")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert "samesite=strict" in r.headers.get("set-cookie", "").lower()


def test_post_sem_csrf_recusado(client, auth):
    r = client.post("/hosts", data={"url": "https://a.pt/"}, headers={"HX-Request": "true"})
    assert r.status_code == 403


def test_criar_editar_desativar_remover_host(client, auth, store):
    r = client.post(
        "/hosts",
        headers=auth,
        data={
            "url": "https://Novo.pt/x",
            "wpscan_enabled": "on",
            "greenbone_enabled": "off",
            "enabled": "on",
            "environment": "PRD",
        },
    )
    assert r.status_code == 204 and r.headers["HX-Redirect"] == "/hosts"
    host = store.get_host_by_name("novo.pt")
    assert host and host.url == "https://novo.pt/x"

    r = client.post("/hosts", headers=auth, data={"url": "https://novo.pt/", "wpscan_enabled": "on"})
    assert r.status_code == 422 and "já existe" in r.text

    r = client.post("/hosts", headers=auth, data={"url": "nao valido", "wpscan_enabled": "on"})
    assert r.status_code == 422 and "has-error" in r.text

    r = client.post(
        f"/hosts/{host.id}",
        headers=auth,
        data={
            "url": "https://novo.pt/x",
            "wpscan_enabled": "on",
            "greenbone_enabled": "on",
            "scan_target": "10.0.0.9",
            "enabled": "on",
            "notes": "nota",
        },
    )
    assert r.status_code == 204
    host = store.get_host(host.id)
    assert host.greenbone_enabled and host.scan_target == "10.0.0.9" and host.notes == "nota"

    r = client.post(f"/hosts/{host.id}/toggle", headers=auth)
    assert r.status_code == 200 and "row-off" in r.text and "desativado" in r.headers["HX-Trigger"]
    assert store.get_host(host.id).enabled is False

    r = client.post(f"/hosts/{host.id}/delete", headers={**auth, "HX-Target": f"host-{host.id}"})
    assert r.status_code == 200 and store.get_host(host.id) is None


def test_importacao_em_lote(client, auth, store):
    store.save_host(Host(name="existe.pt", url="https://existe.pt/"))
    r = client.post(
        "/hosts/bulk",
        headers=auth,
        data={"lines": "https://a.pt/\nb.pt ; DEV\nexiste.pt", "environment": "PRD", "wpscan_enabled": "on"},
    )
    assert r.status_code == 204
    names = {h.name for h in store.list_hosts()}
    assert names == {"a.pt", "b.pt", "existe.pt"}
    assert store.get_host_by_name("b.pt").environment == "DEV"

    r = client.post("/hosts/bulk", headers=auth, data={"lines": "c.pt\n!!!", "wpscan_enabled": "on"})
    assert r.status_code == 422 and "linha 2" in r.text
    assert store.get_host_by_name("c.pt") is None  # tudo ou nada


def test_correr_agora(client, auth, store, engine):
    h = store.save_host(Host(name="a.pt", url="https://a.pt/"))
    r = client.post(f"/hosts/{h.id}/run/wpscan", headers=auth)
    assert r.status_code == 204 and "em fila" in r.headers["HX-Trigger"]
    assert engine.submitted == [("wpscan", "execute_wpscan_batch")]
    r = client.post(f"/hosts/{h.id}/run/wpscan", headers=auth)
    assert r.status_code == 409  # já há uma em fila
    r = client.post(f"/hosts/{h.id}/run/greenbone", headers=auth)
    assert r.status_code == 409  # Greenbone não está ativo para o host


def test_paginas_renderizam(client, auth, store):
    h = store.save_host(Host(name="a.pt", url="https://a.pt/", greenbone_enabled=True))
    run = store.save_run(
        Run(
            host_id=h.id,
            host_name=h.name,
            source=Source.WPSCAN,
            status=RunStatus.FAILED,
            error_message="falhou <script>",
            stats={"by_severity": {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0}},
        )
    )
    store.write_artifact(run.id, "raw.json", b'{"a": 1}')
    for path in [
        "/",
        "/?partial=matrix",
        "/hosts",
        f"/hosts/{h.id}",
        "/runs",
        "/runs?status=failed&source=wpscan",
        f"/runs/{run.id}",
        "/errors?days=30",
        "/settings",
        "/hosts/new",
        f"/hosts/{h.id}/edit",
        "/hosts/bulk",
    ]:
        r = client.get(path)
        assert r.status_code == 200, path
    page = client.get(f"/runs/{run.id}").text
    assert "falhou &lt;script&gt;" in page  # escapado
    assert client.get(f"/runs/{run.id}?partial=1").status_code == 286  # terminada: pára o polling
    assert client.get("/runs?status=xpto").status_code == 400
    assert client.get("/hosts/naoexiste").status_code == 404
    assert client.get(f"/runs/{run.id}/artifacts/raw.json").json() == {"a": 1}
    assert client.get(f"/runs/{run.id}/artifacts/..%2Fhosts.json").status_code == 404
    exported = client.get("/hosts/export.json")
    assert exported.json()["hosts"][0]["name"] == "a.pt"


def test_segredos_nao_aparecem(client, auth):
    html = client.get("/settings").text
    for secret in ["dd-token", "wp-token", "gb-pass", "segredo-de-teste"]:
        assert secret not in html


def test_acoes_em_lote(client, auth, store, engine):
    store.save_host(Host(name="a.pt", url="https://a.pt/"))
    r = client.post("/actions/batch/wpscan", headers=auth)
    assert r.status_code == 204 and "1 host" in r.headers["HX-Trigger"]
    r = client.post("/actions/batch/greenbone", headers=auth)
    assert "Nenhum host" in r.headers["HX-Trigger"]
    assert client.post("/actions/health", headers=auth).status_code == 204
