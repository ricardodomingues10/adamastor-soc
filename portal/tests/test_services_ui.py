from __future__ import annotations

import json
import os
import re

import pytest
import responses
from fastapi.testclient import TestClient
from starlette.datastructures import FormData

from socportal.catalog import FUNCTIONS, TEMPLATES, coverage
from socportal.forms import build_service, values_from_template
from socportal.monitor import Monitor
from socportal.probes import auth_value, extract_version
from socportal.registry import ProbeDef, Registry
from socportal.ui_store import ServiceStore
from socportal.web.app import create_app

from .conftest import soc_status


def form_from_values(v: dict, **extra: str) -> FormData:
    items: list[tuple[str, str]] = []
    for k in ("template", "name", "id", "group", "function", "description", "link", "api_url", "location", "latest"):
        items.append((k, str(v.get(k) or "")))
    for d in v.get("depends_on", []):
        items.append(("depends_on", d))
    for i, p in enumerate(v.get("probes", [])):
        for f in (
            "type",
            "name",
            "url",
            "token_env",
            "auth_header",
            "auth_scheme",
            "expect",
            "contains",
            "version_path",
            "version_regex",
            "service",
            "component",
        ):
            items.append((f"p{i}_{f}", str(p.get(f) or "")))
    items += list(extra.items())
    return FormData(items)


# ---------------------------------------------------------------------------- catálogo


@pytest.mark.parametrize("template", [t["id"] for t in TEMPLATES])
def test_todos_os_modelos_geram_um_servico_valido(template, tmp_path):
    v = values_from_template(template)
    if not v["name"]:
        v["name"] = "Serviço de teste"
    built = build_service(form_from_values(v), ServiceStore(tmp_path))
    s = built.service
    assert s.origin == "ui" and s.template == template
    for p in s.probes:
        resolved = s.resolve(p)
        assert resolved.url is None or not resolved.url.startswith("/"), resolved.url


def test_funcoes_e_cobertura(settings):
    reg = Registry(settings.config_file)
    cov = {c["id"]: [s.id for s in c["services"]] for c in coverage(reg.config.services)}
    assert set(cov) == set(FUNCTIONS)
    assert sorted(cov["vuln"]) == ["defectdojo", "greenbone", "vulnflux"]  # pelos ids dos modelos
    assert cov["cti"] == []
    every = {t["function"] for t in TEMPLATES if t.get("function")}
    assert every == set(FUNCTIONS), "cada função tem pelo menos um modelo"


def test_auth_e_versao():
    assert auth_value("Bearer", "x") == "Bearer x"
    assert auth_value("", "x") == "x"
    assert auth_value("Basic", "u:p") == "Basic dTpw"

    class R:
        def __init__(self, data=None, text=""):
            self._d, self.text = data, text

        def json(self):
            if self._d is None:
                raise ValueError
            return self._d

    p = ProbeDef(type="http", url="/", version_path="version.number")
    assert extract_version(R({"version": {"number": "2.19.1"}}), p) == "2.19.1"
    assert extract_version(R({"version": {}}), p) is None
    assert extract_version(R(None, "html"), p) is None
    rx = ProbeDef(type="http", url="/", version_regex=r'"major":(\d+),"minor":(\d+),"revision":(\d+)')
    assert extract_version(R(text='{"version":{"major":2,"minor":12,"revision":3}}'), rx) == "2.12.3"


# ---------------------------------------------------------------------------- interface


@pytest.fixture
def portal(settings):
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rs:
        rs.get("http://vulnflux:8080/api/status", json=soc_status())
        rs.get("http://dd:8080/login", body="<p>Version 2.51.2 (x)</p>")
        rs.get("http://dd:8080/api/v2/products/", json={"count": 3})
        rs.get(re.compile(r"https://api\.github\.com/.*"), status=404)
        rs.get("https://misp.lab/servers/getVersion.json", json={"version": "2.5.21"})
        rs.get("https://grafana.lab/api/health", json={"database": "ok", "version": "11.4.0"})
        m = Monitor(settings)
        m.run_once()
        app = create_app(settings, m, start=False)
        with TestClient(app) as c:
            page = c.get("/login")
            tok = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
            c.post("/login", data={"username": "admin", "password": "pw-teste", "csrf_token": tok, "next": "/"})
            csrf = re.search(r'name="csrf-token" content="([^"]+)"', c.get("/").text).group(1)
            yield c, m, csrf, rs


def post_form(c, url, v, csrf, **extra):
    data: dict[str, list[str]] = {"csrf_token": [csrf]}
    for k, val in form_from_values(v, **extra).multi_items():
        data.setdefault(k, []).append(val)
    return c.post(url, data=data, follow_redirects=False)


def test_catalogo_e_formulario(portal):
    c, m, csrf, _ = portal
    html = c.get("/catalog").text
    assert "Threat intelligence" in html and "em falta" in html
    assert 'href="/services/new?template=misp"' in html
    form = c.get("/services/new?template=misp").text
    assert 'value="MISP"' in form and 'name="p0_token"' in form


def test_criar_testar_editar_remover(portal, settings):
    c, m, csrf, rs = portal
    v = values_from_template("misp")
    v["link"] = "https://misp.lab"
    # testar antes de gravar: usa a credencial escrita, sem gravar nada
    r = post_form(c, "/services/test", v, csrf, p0_token="chave-secreta")
    assert r.status_code == 200 and "2.5.21" in r.text
    call = [x for x in rs.calls if "getVersion" in x.request.url][-1]
    assert call.request.headers["Authorization"] == "chave-secreta"
    assert not (settings.data_dir / "services.json").exists()

    r = post_form(c, "/services", v, csrf, p0_token="chave-secreta")
    assert r.status_code == 303 and r.headers["location"] == "/s/misp?criado=1"
    raw = (settings.data_dir / "services.json").read_text()
    assert "chave-secreta" not in raw  # só a referência ao ficheiro
    secret = settings.data_dir / "secrets" / "misp.0.token"
    assert secret.read_text() == "chave-secreta" and oct(secret.stat().st_mode & 0o777) == "0o600"
    svc = m.config.get("misp")
    assert svc.origin == "ui" and svc.group == "Threat intelligence"
    m.run_once()
    assert m.state("misp").status == "ok" and m.state("misp").version == "2.5.21"
    detail = c.get("/s/misp").text
    assert "/s/misp/edit" in detail and "interface (editável aqui)" in detail
    assert c.get("/catalog").text.count("no portal") >= 1

    # editar sem escrever a credencial mantém-na
    v["description"] = "MISP do laboratório"
    r = post_form(c, "/s/misp", v, csrf, editing="misp", p0_has_token="1")
    assert r.status_code == 303
    assert m.config.get("misp").description == "MISP do laboratório"
    assert m.config.get("misp").probes[0].token() == "chave-secreta"
    # apagar a credencial
    post_form(c, "/s/misp", v, csrf, editing="misp", p0_has_token="1", p0_clear_token="on")
    assert m.config.get("misp").probes[0].token() is None and not secret.exists()

    r = c.post("/s/misp/delete", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303 and m.config.get("misp") is None


def test_erros_do_formulario(portal):
    c, m, csrf, _ = portal
    # id igual a um serviço do portal.yaml
    v = values_from_template("defectdojo")
    v["link"] = "https://dd2.lab"
    r = post_form(c, "/services", v, csrf)
    assert r.status_code == 422 and "já existe" in r.text
    # caminho relativo sem link nem URL das verificações
    v = values_from_template("grafana")
    v["link"] = ""
    r = post_form(c, "/services", v, csrf)
    assert r.status_code == 422 and "relativo" in r.text
    # serviços do portal.yaml não se editam na interface
    assert c.get("/s/defectdojo/edit").status_code == 409
    assert c.post("/s/defectdojo/delete", data={"csrf_token": csrf}).status_code == 404


def test_dependencias_e_grafo(portal):
    c, m, csrf, _ = portal
    v = values_from_template("grafana")
    v["link"] = "https://grafana.lab"
    v["depends_on"] = ["vulnflux"]
    assert post_form(c, "/services", v, csrf).status_code == 303
    m.run_once()
    assert ("grafana", "vulnflux") in {(e["from"], e["to"]) for e in m.edges()}
    assert m.state("grafana").version == "11.4.0"
    assert "Cobertura do SOC" in c.get("/").text


def test_servicos_da_interface_invalidos_nao_estragam_o_ficheiro(settings):
    path = settings.data_dir / "services.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"services": [{"id": "defectdojo", "name": "Duplicado"}]}))
    reg = Registry(settings.config_file, path)
    assert [s.id for s in reg.config.services] == ["vulnflux", "greenbone", "defectdojo"]
    assert "ignorados" in reg.error
    path.write_text(json.dumps({"services": [{"id": "misp", "name": "MISP", "link": "https://m"}]}))
    os.utime(path, (5, 5))
    reg.reload()
    assert reg.error is None and reg.config.get("misp").origin == "ui"
