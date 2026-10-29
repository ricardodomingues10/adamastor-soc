from __future__ import annotations

import requests
import responses

from socportal.probes import FAIL, OFF, OK, UNKNOWN, WARN, Prober, worst
from socportal.registry import ProbeDef

from .conftest import soc_status

LOGIN_HTML = "<html><footer><p class='mt-2'>Version 2.51.2 (abc123)</p></footer></html>"


def test_worst():
    assert worst([OK, OK]) == OK
    assert worst([OK, WARN, OFF]) == WARN
    assert worst([OFF, OFF]) == OFF
    assert worst([OK, OFF]) == OK
    assert worst([OK, FAIL, WARN]) == FAIL
    assert worst([]) == UNKNOWN


@responses.activate
def test_http_ok_e_texto(settings):
    responses.get("http://x/health", body="pong")
    p = Prober(settings)
    assert p.run(ProbeDef(type="http", url="http://x/health", contains="pong")).status == OK
    assert p.run(ProbeDef(type="http", url="http://x/health", contains="nada")).status == FAIL


@responses.activate
def test_http_codigo_inesperado_e_ligacao_recusada(settings):
    responses.get("http://x/health", status=502)
    responses.get("http://y/", body=requests.ConnectionError("recusada"))
    p = Prober(settings)
    r = p.run(ProbeDef(type="http", url="http://x/health"))
    assert (r.status, r.message) == (FAIL, "respondeu 502")
    r = p.run(ProbeDef(type="http", url="http://y/", name="UI"))
    assert r.status == FAIL and "inacessível" in r.message and r.probe == "UI"


@responses.activate
def test_defectdojo_api_e_versao(settings, token_file):
    responses.get("http://dd:8080/login", body=LOGIN_HTML)
    responses.get("http://dd:8080/api/v2/products/", json={"count": 7, "results": []})
    r = Prober(settings).run(ProbeDef(type="defectdojo", url="http://dd:8080", token_file=str(token_file)))
    assert r.status == OK
    assert r.version == "2.51.2"
    assert "7 products" in r.message
    api_call = [c for c in responses.calls if "/api/v2/products/" in c.request.url][0]
    assert api_call.request.headers["Authorization"] == "Token dd-secret"


@responses.activate
def test_defectdojo_versao_pelo_manifesto(settings, token_file):
    responses.get("http://dd:8080/login", body="<html>sem versão</html>")
    responses.get("http://dd:8080/api/v2/export/manifest/", json={"source": {"version": "3.4.1"}})
    responses.get("http://dd:8080/api/v2/products/", json={"count": 0})
    r = Prober(settings).run(ProbeDef(type="defectdojo", url="http://dd:8080", token_file=str(token_file)))
    assert r.version == "3.4.1"


@responses.activate
def test_defectdojo_token_rejeitado(settings, token_file):
    responses.get("http://dd:8080/login", body=LOGIN_HTML)
    responses.get("http://dd:8080/api/v2/products/", status=401)
    r = Prober(settings).run(ProbeDef(type="defectdojo", url="http://dd:8080", token_file=str(token_file)))
    assert r.status == FAIL and "token rejeitado" in r.message
    assert r.version == "2.51.2"  # a versão vem da página, mesmo com o token errado


@responses.activate
def test_soc_status(settings, monkeypatch):
    monkeypatch.setenv("T", "tok")
    responses.get("http://vf/api/status", json=soc_status())
    r = Prober(settings).run(ProbeDef(type="soc-status", url="http://vf/api/status", token_env="T"))
    assert r.status == OK and r.version == "0.2.0"
    assert r.dependencies == {"defectdojo": "ok", "greenbone": "off"}
    assert "greenbone" in r.components
    assert r.jobs[0]["last_status"] == "ok"
    assert responses.calls[0].request.headers["Authorization"] == "Bearer tok"


@responses.activate
def test_soc_status_contrato_errado_e_404(settings):
    responses.get("http://vf/api/status", json={"status": "ok"})
    responses.get("http://vf2/api/status", status=404)
    p = Prober(settings)
    assert "contrato desconhecido" in p.run(ProbeDef(type="soc-status", url="http://vf/api/status")).message
    assert "versão antiga" in p.run(ProbeDef(type="soc-status", url="http://vf2/api/status")).message
    responses.get("http://vf3/api/status", status=404, json={"error": "desligado: define VF_STATUS_TOKEN"})
    assert "VF_STATUS_TOKEN" in p.run(ProbeDef(type="soc-status", url="http://vf3/api/status")).message


def test_soc_component(settings):
    comps = {"vulnflux": {"greenbone": {"status": "off", "message": "parado", "freshness": [{"id": "NVT"}]}}}
    p = Prober(settings)
    r = p.run(ProbeDef(type="soc-component", service="vulnflux", component="greenbone"), comps)
    assert (r.status, r.message, len(r.freshness)) == (OFF, "parado", 1)
    r = p.run(ProbeDef(type="soc-component", service="vulnflux", component="misp"), comps)
    assert r.status == UNKNOWN
    r = p.run(ProbeDef(type="soc-component", service="outro", component="x"), comps)
    assert r.status == UNKNOWN


@responses.activate
def test_misp(settings, monkeypatch):
    monkeypatch.setenv("MISP_KEY", "k")
    responses.get("https://misp/servers/getVersion.json", json={"version": "2.5.21"})
    r = Prober(settings).run(ProbeDef(type="misp", url="https://misp", token_env="MISP_KEY"))
    assert (r.status, r.version) == (OK, "2.5.21")
    assert responses.calls[0].request.headers["Authorization"] == "k"


def test_tcp_porta_fechada(settings):
    r = Prober(settings).run(ProbeDef(type="tcp", url="127.0.0.1:1", timeout=1))
    assert r.status == FAIL
