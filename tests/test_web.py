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


# ---------------------------------------------------------------------------- prioridades e estado


def test_pagina_prioridades(client, auth, store):
    r = client.get("/risk")
    assert r.status_code == 200 and "Ainda sem prioridades calculadas" in r.text
    store.set_state(
        "risk_summary",
        {
            "generated_at": "2026-10-29T06:20:00+00:00",
            "updated_at": "2026-10-29T06:20:00+00:00",
            "stats": {"by_priority": {"P1": 1, "P2": 0, "P3": 0, "P4": 0}, "kev": 1, "products_missing": []},
            "top": [
                {
                    "finding_id": 10,
                    "title": "Plugin X RCE",
                    "host": "www.exemplo.pt",
                    "severity": "Critical",
                    "priority": "P1",
                    "score": 84,
                    "cves": ["CVE-2023-39312"],
                    "exploits": ["metasploit"],
                    "kev": True,
                    "epss_percentile": 0.97,
                    "planned": "2026-11-05",
                    "reasons": ["CVSS 9.8"],
                }
            ],
        },
    )
    html = client.get("/risk").text
    assert "Plugin X RCE" in html and 'href="https://dd.test/finding/10"' in html
    assert 'width="84"' in html  # barra em SVG (sem estilos inline: CSP)
    assert "Plugin X RCE" not in client.get("/risk?p=P3").text


def test_acao_prioridades(client, auth, engine):
    r = client.post("/actions/risk?download=0", headers=auth)
    assert r.status_code == 204
    assert ("risk", "execute_risk") in engine.submitted
    # um de cada vez
    assert client.post("/actions/risk", headers=auth).status_code == 409


def test_formulario_tem_contexto_de_risco(client, auth):
    html = client.get("/hosts/new", headers=auth).text
    assert 'name="criticality"' in html and 'name="exposure"' in html and 'name="data_class"' in html


def test_api_status_contrato(client, settings, store):
    from pydantic import SecretStr

    assert client.get("/api/status").status_code == 404  # sem VF_STATUS_TOKEN: desligado
    settings.status_token = SecretStr("st-123")
    assert client.get("/api/status").status_code == 401
    assert client.get("/api/status", headers={"Authorization": "Bearer errado"}).status_code == 401
    store.set_state(
        "health",
        {
            "defectdojo": {
                "label": "DefectDojo",
                "status": "ok",
                "message": "12 ms",
                "checked_at": "2026-10-29T10:00:00+00:00",
            },
            "greenbone": {"label": "Greenbone", "status": "off", "message": "parado (on-demand)", "details": {}},
        },
    )
    store.set_state(
        "greenbone_feeds", {"versions": {"NVT": "202610280512", "SCAP": "202610280512"}, "syncing": ["SCAP"]}
    )
    data = client.get("/api/status", headers={"Authorization": "Bearer st-123"}).json()
    assert data["schema"] == "soc-status/1" and data["service"] == "vulnflux"
    assert data["status"] == "ok" and data["dependencies"]["defectdojo"] == "ok"
    gb = data["components"]["greenbone"]
    assert gb["status"] == "off"
    feeds = {f["id"]: f for f in gb["freshness"]}
    assert feeds["greenbone_nvt"]["status"] == "off" and feeds["greenbone_nvt"]["updated_at"].startswith(
        "2026-10-28T05:12"
    )
    assert feeds["greenbone_scap"]["status"] == "warn"  # a carregar
    assert feeds["greenbone_cert"]["status"] == "unknown"
    assert any(f["id"] == "wpscan_db" for f in data["freshness"])


def test_run_em_json(client, auth, store):
    r = client.post("/actions/risk", headers=auth)
    run_id = r.headers["X-Run-Id"]
    data = client.get(f"/runs/{run_id}.json").json()
    assert data["id"] == run_id and data["source"] == "risk" and data["host_id"] == "*"
    assert client.get(f"/runs/{run_id}").status_code == 200  # página do run de todos os hosts
