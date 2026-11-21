"""Vigilante: estado inicial sem alertas, deteção do que é novo, encaminhamento e envio (email/ticket)."""

from __future__ import annotations

import json
import re

import pytest
import responses
from pydantic import SecretStr

from vulnflux.models import Host
from vulnflux.watch import notify, sources, watcher
from vulnflux.wordpress import inventory
from vulnflux.wordpress.vulndb import VulnCache

WPORG = "https://api.wordpress.org"


class FakeSMTP:
    sent: list = []

    def __init__(self, host, port, timeout=None):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        pass

    def login(self, user, password):
        pass

    def send_message(self, msg):
        FakeSMTP.sent.append(msg)


@pytest.fixture
def ws(settings, monkeypatch):
    FakeSMTP.sent = []
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    return settings.model_copy(
        update={
            "watch_github_repos": "n8n-io/n8n",
            "watch_wpscan_refresh": 0,
            "smtp_host": "smtp.exemplo.test",
            "smtp_from": "soc@exemplo.test",
            "watch_email_to": "soc@exemplo.test",
            "watch_routes": "web=web@exemplo.test",
            "ticket_mode": "webhook",
            "ticket_webhook_url": "https://n8n.exemplo.test/webhook/tickets",
            "ticket_webhook_token": SecretStr("tok"),
        }
    )


@pytest.fixture
def sites(store):
    a = store.save_host(Host(name="a.exemplo.pt", url="https://a.exemplo.pt/", tags=["equipa:web"]))
    b = store.save_host(Host(name="b.exemplo.pt", url="https://b.exemplo.pt/"))
    for host, cf7 in ((a, "5.7.1"), (b, "5.9.8")):
        inventory.record(
            store,
            host.id,
            {
                "url": host.url,
                "name": host.name,
                "wordpress": "6.4.1",
                "themes": {"avada": {"version": "7.11.1", "latest": None}},
                "plugins": {"contact-form-7": {"version": cf7, "latest": None}},
            },
        )
    return a, b


def mock_sources(rsps, *, core="6.4.1", cf7="5.9.8", n8n="1.60.0"):
    rsps.get(
        re.compile(rf"{WPORG}/core/version-check/1.7/.*"),
        json={"offers": [{"response": "upgrade", "current": core}]},
    )
    rsps.get(re.compile(rf"{WPORG}/plugins/info/1.2/.*"), json={"version": cf7, "last_updated": "2026-11-01"})
    rsps.get(re.compile(rf"{WPORG}/themes/info/1.2/.*"), json={"error": "Theme not found"})  # tema premium
    rsps.get(
        "https://api.github.com/repos/n8n-io/n8n/releases/latest",
        json={"tag_name": n8n, "html_url": "https://github.com/n8n-io/n8n/releases"},
    )
    rsps.post("https://n8n.exemplo.test/webhook/tickets", json={"id": "INC-1"})


def cache_vulns(settings, vulns):
    VulnCache(settings).put(
        "plugin", "contact-form-7", {"not_found": False, "latest_version": "5.9.8", "vulnerabilities": vulns}
    )


@responses.activate
def test_primeira_verificacao_so_guarda_estado(store, ws, sites):
    mock_sources(responses)
    cache_vulns(ws, [{"id": "v1", "title": "Antiga", "fixed_in": "5.8.4"}])
    summary = watcher.run_watch(store, ws)
    assert summary["new_events"] == 0
    assert not FakeSMTP.sent
    assert summary["errors"] == []
    state = store.get_state(watcher.STATE)
    assert state["versions"]["plugin:contact-form-7"] == "5.9.8"
    assert "wpscan:v1" in state["seen"]


@responses.activate
def test_nova_vulnerabilidade_abre_ticket_e_envia_email_a_equipa(store, ws, sites):
    mock_sources(responses)
    cache_vulns(ws, [])
    watcher.run_watch(store, ws)  # estado inicial
    cache_vulns(
        ws,
        [
            {
                "id": "v2",
                "title": "CF7 < 5.8.5 - RCE",
                "fixed_in": "5.8.5",
                "cvss": {"score": "9.8"},
                "references": {"cve": ["2026-0001"], "wpvulndb": ["v2"]},
            }
        ],
    )
    summary = watcher.run_watch(store, ws)
    assert summary["new_events"] == 1 and summary["tickets"] == 1 and summary["emails"] == 1
    (event,) = store.get_state(watcher.EVENTS)
    assert event["severity"] == "critical"
    assert [s["name"] for s in event["sites"]] == ["a.exemplo.pt"]  # o b já tem 5.9.8
    assert event["teams"] == ["web"]
    assert event["ticket"] == "INC-1"
    hook = [c for c in responses.calls if c.request.method == "POST"][0].request
    assert hook.headers["Authorization"] == "Bearer tok"
    assert json.loads(hook.body)["event_id"] == event["id"]
    (mail,) = FakeSMTP.sent
    assert mail["To"] == "web@exemplo.test"
    assert "Crítica" in mail["Subject"]
    # Repetir não volta a alertar
    again = watcher.run_watch(store, ws)
    assert again["new_events"] == 0 and len(FakeSMTP.sent) == 1


@responses.activate
def test_nova_versao_so_alerta_sites_desatualizados_e_ferramentas(store, ws, sites):
    mock_sources(responses)
    watcher.run_watch(store, ws)
    responses.reset()
    mock_sources(responses, core="6.7.0", cf7="6.0.0", n8n="1.61.0")
    summary = watcher.run_watch(store, ws)
    events = {e["id"]: e for e in store.get_state(watcher.EVENTS)}
    assert "release:plugin:contact-form-7:6.0.0" in events
    assert len(events["release:plugin:contact-form-7:6.0.0"]["sites"]) == 2
    assert "release:wordpress:core:6.7.0" in events
    assert "release:tool:n8n-io/n8n:1.61.0" in events
    assert summary["tickets"] == 0  # versões não abrem tickets
    assert summary["emails"] == 2  # um para a equipa web, outro para o endereço geral


@responses.activate
def test_envio_falhado_fica_pendente(store, ws, sites, monkeypatch):
    mock_sources(responses)
    cache_vulns(ws, [])
    watcher.run_watch(store, ws)
    cache_vulns(ws, [{"id": "v3", "title": "XSS", "fixed_in": "5.8.0", "cvss": {"score": "7.5"}}])
    responses.replace(responses.POST, "https://n8n.exemplo.test/webhook/tickets", status=502)
    first = watcher.run_watch(store, ws)
    assert first["failed"] == 1 and first["tickets"] == 0
    (event,) = store.get_state(watcher.EVENTS)
    assert "502" in event["ticket_error"] and event["attempts"] == 1
    responses.replace(responses.POST, "https://n8n.exemplo.test/webhook/tickets", json={"id": "INC-9"})
    second = watcher.run_watch(store, ws)
    assert second["tickets"] == 1
    assert store.get_state(watcher.EVENTS)[0]["ticket"] == "INC-9"


def test_rss_atom_e_entidades_bloqueadas(monkeypatch):
    xml = b"""<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<rss><channel><item><title>Aviso &x; contact form 7</title><link>https://x/1</link><guid>1</guid></item>
</channel></rss>"""

    class R:
        content = xml

        def raise_for_status(self):
            pass

    monkeypatch.setattr(sources, "_get", lambda *a, **k: R())
    obs = sources.Observations()
    sources.rss(obs, "CERT", "https://cert.test/feed")
    assert len(obs.advisories) == 1
    assert "root:" not in obs.advisories[0].title


def test_intervalos_wordfence():
    r = [{"from": "*", "from_inclusive": True, "to": "5.8.4", "to_inclusive": False}]
    assert sources.in_ranges("5.8.3", r)
    assert not sources.in_ranges("5.8.4", r)
    assert sources.in_ranges(None, r)
    r2 = [{"from": "2.0", "from_inclusive": True, "to": "2.3", "to_inclusive": True}]
    assert sources.in_ranges("2.3", r2) and not sources.in_ranges("1.9", r2)


def test_rotas_por_equipa(ws):
    assert notify.recipients(ws, ["web"]) == ["web@exemplo.test"]
    assert notify.recipients(ws, ["sem-rota"]) == ["soc@exemplo.test"]
    assert notify.parse_routes("a=x@y.pt, z@y.pt; b = w@y.pt") == {"a": ["x@y.pt", "z@y.pt"], "b": ["w@y.pt"]}
    assert notify.teams_of(["equipa:Web", "prd"]) == ["web"]


def test_severidade_por_cvss():
    assert watcher.severity_of(9.8) == "critical"
    assert watcher.severity_of(7.0) == "high"
    assert watcher.severity_of(None) == "medium"
    assert watcher.severity_of(2.0) == "low"


def test_canais_com_token_so_por_tls(settings):
    from vulnflux.config import Settings

    for ok in ("https://n8n.exemplo.pt/webhook/x", "http://n8n:5678/webhook/x", "http://localhost:8080/h"):
        assert Settings(_env_file=None, ticket_webhook_url=ok).ticket_webhook_url == ok
    for bad in ("http://n8n.exemplo.pt/webhook/x", "ftp://x/y", "http://10.0.0.5/h"):
        with pytest.raises(ValueError):
            Settings(_env_file=None, ticket_webhook_url=bad)
    with pytest.raises(ValueError):
        Settings(_env_file=None, watch_wordfence_url="http://www.wordfence.com/feed")
    with pytest.raises(ValueError):
        Settings(_env_file=None, smtp_host="smtp.x", smtp_user="u", smtp_starttls=False)
    assert Settings(_env_file=None, smtp_host="smtp.x", smtp_user="u", smtp_starttls=False, smtp_ssl=True).smtp_ssl


def test_wordfence_lido_aos_bocados_e_com_limite(monkeypatch, settings):
    import io
    import json as _json

    feed = {
        "abc": {
            "id": "abc",
            "title": "CF7 XSS",
            "cvss": {"score": 6.1},
            "cve": "CVE-2026-1",
            "software": [
                {
                    "type": "plugin",
                    "slug": "contact-form-7",
                    "patched_versions": ["5.9.9"],
                    "affected_versions": {
                        "* - 5.9.8": {
                            "from_version": "*",
                            "to_version": "5.9.8",
                            "from_inclusive": True,
                            "to_inclusive": True,
                        }
                    },
                }
            ],
        },
        "zzz": {"id": "zzz", "title": "Outro", "software": [{"type": "plugin", "slug": "nao-instalado"}]},
    }
    body = _json.dumps(feed).encode()

    class R:
        status_code = 200

        def __init__(self, data):
            self.data = data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size):
            stream = io.BytesIO(self.data)
            while chunk := stream.read(7):
                yield chunk

    s = settings.model_copy(update={"watch_wordfence_token": SecretStr("k")})
    monkeypatch.setattr(sources.requests, "get", lambda *a, **k: R(body))
    obs = sources.Observations()
    sources.wordfence(obs, s, {("plugin", "contact-form-7")})
    assert [v.vuln_id for v in obs.vulns] == ["wordfence:abc"] and obs.vulns[0].score == 6.1
    assert obs.vulns[0].fixed_in == "5.9.9" and not obs.errors

    obs = sources.Observations()
    monkeypatch.setattr(sources.requests, "get", lambda *a, **k: R(b"x" * (2 * 1024 * 1024)))
    sources.wordfence(obs, s.model_copy(update={"watch_wordfence_max_mb": 1}), {("plugin", "contact-form-7")})
    assert obs.errors and "maior do que 1 MB" in obs.errors[0]


@responses.activate
def test_componente_novo_vulneravel_alerta_e_ids_por_idade(store, ws, sites):
    mock_sources(responses)
    cache_vulns(ws, [])
    watcher.run_watch(store, ws)  # estado inicial: fonte WPScan fica "pronta"
    # Um plugin acabado de instalar num site, que já tem uma vulnerabilidade publicada
    a, _b = sites
    entry = inventory.load(store)[a.id]
    entry["plugins"]["forminator"] = {"version": "1.0", "latest": None}
    inventory.record(store, a.id, entry)
    VulnCache(ws).put(
        "plugin",
        "forminator",
        {
            "vulnerabilities": [
                {"id": "fm1", "title": "Forminator < 1.2 - RCE", "fixed_in": "1.2", "cvss": {"score": "9.8"}}
            ]
        },
    )
    responses.reset()
    mock_sources(responses)
    summary = watcher.run_watch(store, ws)
    assert summary["new_events"] == 1
    ev = store.get_state(watcher.EVENTS)[0]
    assert ev["title"].startswith("Componente novo com vulnerabilidade conhecida") and ev["severity"] == "critical"
    state = store.get_state(watcher.STATE)
    assert isinstance(state["seen"], dict) and "wpscan:fm1" in state["seen"]


def test_ids_vistos_migram_e_cortam_pelos_mais_antigos(store, monkeypatch):
    monkeypatch.setattr(watcher, "MAX_SEEN", 3)
    state = {"seen": ["a", "b"], "baselined": []}  # formato antigo (lista)
    obs = sources.Observations()
    watcher.detect(store, {}, obs, state, set())
    assert set(state["seen"]) == {"a", "b"}
    state["seen"] = {"zz-velho": "2026-01-01", "aa-novo": "2026-11-20", "mm": "2026-06-01", "bb": "2026-10-01"}
    watcher.detect(store, {}, obs, state, set())
    assert set(state["seen"]) == {"aa-novo", "bb", "mm"}  # sai o mais antigo, não o último por ordem alfabética
