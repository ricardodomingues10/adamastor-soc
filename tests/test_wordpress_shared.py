"""Modo partilhado do WPScan: enumeração sem chave + vulnerabilidades por componente com cache."""

from __future__ import annotations

import copy
import json
from datetime import timedelta

import pytest
import responses
from pydantic import SecretStr

from test_pipeline import FakeDD
from vulnflux import pipeline
from vulnflux.collectors import wpscan
from vulnflux.collectors.wpscan import ScanOutput
from vulnflux.collectors.wpscan_tokens import TokenPool
from vulnflux.errors import ErrorKind, VFError
from vulnflux.models import Host, RunStatus, Source, Trigger, utcnow
from vulnflux.wordpress import inventory
from vulnflux.wordpress.vulndb import Budget, VulnCache, affects, enrich, fetch_component

API = "https://wpscan.test/api/v3"

CORE = {
    "6.4.1": {
        "release_date": "2023-11-09",
        "status": "insecure",
        "vulnerabilities": [
            {
                "title": "WP < 6.4.2 - POP Chain",
                "fixed_in": "6.4.2",
                "references": {"cve": ["2023-6553"]},
                "cvss": {"score": "8.1"},
            },
        ],
    }
}
CF7 = {
    "contact-form-7": {
        "latest_version": "5.9.8",
        "last_updated": "2024-08-01",
        "vulnerabilities": [
            {"title": "CF7 < 5.8.4 - Upload", "fixed_in": "5.8.4", "references": {"cve": ["2023-6449"]}},
            {"title": "CF7 < 5.0.4 - Antigo", "fixed_in": "5.0.4", "references": {}},
            {"title": "CF7 5.9 - Regressão", "introduced_in": "5.9.0", "fixed_in": "5.9.2", "references": {}},
        ],
    }
}
AVADA = {
    "avada": {
        "latest_version": "7.11.10",
        "vulnerabilities": [
            {"title": "Avada < 7.11.2 - SQLi", "fixed_in": "7.11.2", "references": {"cve": ["2023-39312"]}},
        ],
    }
}


@pytest.fixture
def shared(settings):
    return settings.model_copy(
        update={
            "wpscan_mode": "partilhado",
            "wpscan_api_url": API,
            "wpscan_api_token": SecretStr(""),
            "wpscan_api_tokens": SecretStr("chave-a,chave-b"),
        }
    )


@pytest.fixture
def enumerated(wpscan_raw):
    """O que o WPScan devolve sem chave: componentes e versões, sem vulnerabilidades nem vuln_api."""
    raw = copy.deepcopy(wpscan_raw)
    raw.pop("vuln_api", None)
    raw["version"]["vulnerabilities"] = []
    raw["main_theme"]["vulnerabilities"] = []
    for node in raw["plugins"].values():
        node["vulnerabilities"] = []
    return raw


@pytest.fixture
def fake_enum(monkeypatch, enumerated):
    state = {"calls": []}

    def run_scan(url, output, settings, token=None, *, shared=False, profile=None):
        state["calls"].append((url, token, shared))
        state.setdefault("profiles", []).append(profile)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(enumerated))
        return ScanOutput(exit_code=5, raw=copy.deepcopy(enumerated), stderr="")

    monkeypatch.setattr(wpscan, "run_scan", run_scan)
    monkeypatch.setattr(wpscan, "ensure_database", lambda settings: "BD atual")
    return state


def pool_for(store, settings, remaining=25):
    return TokenPool(settings, store, status_fn=lambda token: {"plan": "free", "requests_remaining": remaining})


def mock_api(rsps, akismet_status=404):
    rsps.get(f"{API}/wordpresses/641", json=CORE)
    rsps.get(f"{API}/plugins/contact-form-7", json=CF7)
    rsps.get(f"{API}/plugins/akismet", status=akismet_status, json={})
    rsps.get(f"{API}/themes/avada", json=AVADA)


def _host(store, name="www.exemplo.pt"):
    return store.save_host(Host(name=name, url=f"https://{name}/", environment="PRD"))


# ------------------------------------------------------------------ versões


@pytest.mark.parametrize(
    ("version", "vuln", "expected"),
    [
        ("5.7.1", {"fixed_in": "5.8.4"}, True),
        ("5.8.4", {"fixed_in": "5.8.4"}, False),
        ("5.10", {"fixed_in": "5.9.9"}, False),  # comparação numérica, não alfabética
        ("5.8.0", {"introduced_in": "5.9.0", "fixed_in": "5.9.2"}, False),
        ("5.9.1", {"introduced_in": "5.9.0", "fixed_in": "5.9.2"}, True),
        ("1.0", {}, True),  # sem correção conhecida: afeta todas
        (None, {"fixed_in": "1.0"}, True),  # versão desconhecida: conta, como no WPScan
        ("2.3.1-beta", {"fixed_in": "2.3.1"}, True),
    ],
)
def test_affects(version, vuln, expected):
    assert affects(version, vuln) is expected


# ------------------------------------------------------------------ API


@responses.activate
def test_fetch_component_formatos(shared):
    mock_api(responses)
    responses.get(f"{API}/plugins/sem-quota", status=429)
    responses.get(f"{API}/plugins/chave-ma", status=401, json={"error": "invalid"})
    core = fetch_component(shared, "wordpress", "6.4.1", "t")
    assert core["vulnerabilities"][0]["fixed_in"] == "6.4.2"
    assert responses.calls[0].request.headers["Authorization"] == "Token token=t"
    plugin = fetch_component(shared, "plugin", "contact-form-7", "t")
    assert plugin["latest_version"] == "5.9.8" and len(plugin["vulnerabilities"]) == 3
    assert fetch_component(shared, "plugin", "akismet", "t") == {"not_found": True, "vulnerabilities": []}
    with pytest.raises(VFError) as exc:
        fetch_component(shared, "plugin", "sem-quota", "t")
    assert exc.value.kind is ErrorKind.QUOTA
    with pytest.raises(VFError) as exc:
        fetch_component(shared, "plugin", "chave-ma", "t")
    assert exc.value.kind is ErrorKind.CONFIG
    with pytest.raises(VFError):
        fetch_component(shared, "plugin", "../etc/passwd", "t")


# ------------------------------------------------------------------ cache


@responses.activate
def test_cache_partilhada_entre_sites(store, shared, enumerated):
    mock_api(responses)
    pool = pool_for(store, shared)
    pool.refresh()
    cache = VulnCache(shared)
    first = enrich(copy.deepcopy(enumerated), cache, pool)
    assert first.budget.used == 4 and first.checked == 4 and not first.unchecked
    second = enrich(copy.deepcopy(enumerated), VulnCache(shared), pool)  # outra instância: lê do disco
    assert second.budget.used == 0 and second.checked == 4
    assert len(responses.calls) == 4


@responses.activate
def test_rotacao_de_chaves_e_quota(store, shared, enumerated):
    # Uma chave responde 429 a tudo; a outra responde. Cada componente é pedido uma vez com sucesso.
    state = {"n": 0}

    def callback(request):
        if request.headers["Authorization"].endswith("chave-a"):
            return (429, {}, "")
        state["n"] += 1
        return (404, {}, "{}")

    responses.add_callback(responses.GET, f"{API}/plugins/contact-form-7", callback=callback)
    responses.add_callback(responses.GET, f"{API}/plugins/akismet", callback=callback)
    responses.add_callback(responses.GET, f"{API}/themes/avada", callback=callback)
    responses.add_callback(responses.GET, f"{API}/wordpresses/641", callback=callback)
    pool = TokenPool(shared, store, status_fn=lambda t: {"requests_remaining": 25 if t == "chave-a" else 10})
    pool.refresh()
    result = enrich(copy.deepcopy(enumerated), VulnCache(shared), pool)
    assert state["n"] == 4 and result.checked == 4
    assert any(s.status == "exhausted" for s in pool.summary())


@responses.activate
def test_sem_quota_usa_cache_antiga(store, shared, enumerated):
    mock_api(responses)
    cache = VulnCache(shared)
    pool = pool_for(store, shared)
    pool.refresh()
    enrich(copy.deepcopy(enumerated), cache, pool)
    for entry in cache.entries.values():  # envelhece a cache
        entry["fetched_at"] = (utcnow() - timedelta(hours=48)).isoformat()
    dry = pool_for(store, shared, remaining=0)
    dry.refresh()
    result = enrich(copy.deepcopy(enumerated), cache, dry)
    assert result.checked == 4 and len(result.stale) == 4 and not result.unchecked
    assert result.vulnerable == 3  # core + CF7 5.8.4 + Avada (os dados antigos continuam a servir)


def test_lookup_sem_chaves_nem_cache(shared):
    look = VulnCache(shared).lookup("plugin", "akismet", None, budget := Budget())
    assert look.entry is None and look.source == "nenhuma" and budget.denied == 1


# ------------------------------------------------------------------ pipeline


@responses.activate
def test_execucao_partilhada_importa_vulns_por_versao(store, shared, fake_enum):
    mock_api(responses)
    host = _host(store)
    pool = pool_for(store, shared)
    pool.refresh()
    dd = FakeDD()
    run = pipeline.execute_wpscan(
        store, shared, pipeline.create_run(store, host, Source.WPSCAN, Trigger.MANUAL).id, dd=dd, pool=pool
    )
    assert run.status is RunStatus.SUCCESS, (run.error_message, run.warnings)
    assert fake_enum["calls"] == [("https://www.exemplo.pt/", None, True)]  # enumeração sem chave
    names = [s.name for s in run.steps]
    assert names[:4] == ["Preparar", "Enumerar (sem chave, perfil rapido)", "Validar", "Vulnerabilidades"]
    titles = {
        f["title"]
        for f in json.loads((store.artifacts_dir / run.id / "defectdojo-generic.json").read_text())["findings"]
    }
    assert any("POP Chain" in t for t in titles)
    assert any("CF7 < 5.8.4" in t for t in titles)
    assert not any("Antigo" in t or "Regressão" in t for t in titles)  # corrigidas ou ainda não introduzidas
    assert dd.calls[0]["close_old_findings"] is True
    assert run.stats["wp_api_requests"] == 4
    inv = inventory.load(store)[host.id]
    assert inv["wordpress"] == "6.4.1"
    cf7 = inv["plugins"]["contact-form-7"]
    assert (cf7["version"], cf7["latest"]) == ("5.7.1", "5.9.8") and cf7["seen_at"]


def test_execucao_sem_quota_nao_fecha_findings(store, shared, fake_enum):
    host = _host(store)
    pool = pool_for(store, shared, remaining=0)
    pool.refresh()
    dd = FakeDD()
    run = pipeline.execute_wpscan(
        store, shared, pipeline.create_run(store, host, Source.WPSCAN, Trigger.MANUAL).id, dd=dd, pool=pool
    )
    assert run.status is RunStatus.WARNING
    assert any("sem dados de vulnerabilidades" in w for w in run.warnings)
    assert dd.calls[0]["close_old_findings"] is False


@responses.activate
def test_lote_partilhado_analisa_todos_e_nao_para_sem_quota(store, shared, fake_enum, monkeypatch):
    mock_api(responses)
    hosts = [_host(store, f"site{i}.exemplo.pt") for i in range(6)]
    ids = pipeline.plan_wpscan_batch(store, shared, Trigger.SCHEDULE)
    assert len(ids) == len(hosts)  # wpscan_shared_batch_size=0: todos
    pool = TokenPool(shared, store, status_fn=lambda t: {"requests_remaining": 2})  # 4 pedidos no total
    summary = pipeline.execute_wpscan_batch(store, shared, ids, dd=FakeDD(), pool=pool)
    assert summary["status"] == "concluído"
    assert summary["api_requests"] == 4  # cada componente pedido uma única vez para os 6 sites
    statuses = {store.get_run(i).status for i in ids}
    assert statuses == {RunStatus.SUCCESS}


def test_modo_por_site_continua_a_exigir_chave(store, settings, fake_enum):
    s = settings.model_copy(update={"wpscan_api_token": SecretStr(""), "wpscan_api_tokens": SecretStr("")})
    host = _host(store)
    run = pipeline.execute_wpscan(
        store, s, pipeline.create_run(store, host, Source.WPSCAN, Trigger.MANUAL).id, dd=FakeDD()
    )
    assert run.status is RunStatus.FAILED and "chave" in run.error_message


def test_modo_aceita_sinonimos(settings):
    assert settings.model_copy(update={}).wpscan_mode == "por_site"
    from vulnflux.config import Settings

    assert Settings(_env_file=None, wpscan_mode="premium").wpscan_mode == "por_site"
    with pytest.raises(ValueError):
        Settings(_env_file=None, wpscan_mode="outro")


def test_prefetch_ordem_justa(store, shared):
    from vulnflux.wordpress.vulndb import prefetch

    cache = VulnCache(shared)
    cache.put("plugin", "antigo", {"vulnerabilities": []})
    cache.entries["plugin:antigo"]["fetched_at"] = (utcnow() - timedelta(hours=30)).isoformat()
    cache.put("plugin", "fresco", {"vulnerabilities": []})
    order = []

    def fake_fetch(settings, kind, slug, token, timeout=20):
        order.append(slug)
        return {"not_found": True, "vulnerabilities": []}

    import vulnflux.wordpress.vulndb as vulndb

    original = vulndb.fetch_component
    vulndb.fetch_component = fake_fetch
    try:
        pool = TokenPool(shared, store, status_fn=lambda t: {"requests_remaining": 1})  # 2 pedidos no total
        pool.refresh()
        budget = prefetch(
            cache,
            pool,
            {("plugin", "antigo"): 9, ("plugin", "novo"): 1, ("plugin", "fresco"): 5, ("plugin", "outro-novo"): 3},
        )
    finally:
        vulndb.fetch_component = original
    assert order == ["outro-novo", "novo"]  # nunca obtidos primeiro; o antigo espera; o fresco não gasta
    assert budget.used == 2


def test_id_da_api_fica_igual_ao_do_cli(store, shared, enumerated):
    """O mesmo finding tem o mesmo unique_id nos dois modos (mudar de modo não duplica)."""
    from vulnflux.converters.wpscan_generic import convert

    VulnCache(shared).put(
        "plugin",
        "contact-form-7",
        {
            "vulnerabilities": [
                {"id": "abc-123", "title": "CF7 XSS", "fixed_in": "9.0", "references": {"cve": ["2026-1"]}}
            ]
        },
    )
    raw = copy.deepcopy(enumerated)
    enrich(raw, VulnCache(shared), None)
    ids = [f["unique_id_from_tool"] for f in convert(raw, include_interesting=False, include_users=False)["findings"]]
    assert "wpscan:plugin:contact-form-7:abc-123" in ids


def test_comando_por_perfil(settings, tmp_path):
    from vulnflux.collectors.wpscan import build_command

    s = settings.model_copy(update={"wpscan_mode": "partilhado"})
    fast = build_command("https://x/", tmp_path / "o.json", s, shared=True)
    assert fast[fast.index("--enumerate") + 1] == "ap,at,cb,dbe,u1-10"
    assert fast[fast.index("--plugins-detection") + 1] == "passive"  # não testa caminhos um a um
    deep = build_command("https://x/", tmp_path / "o.json", s, shared=True, profile="completo")
    assert deep[deep.index("--enumerate") + 1].startswith("p,t,tt") and "mixed" in deep


def test_rapido_mantem_plugins_do_ultimo_scan_completo(store, shared, enumerated):
    from vulnflux.wordpress import inventory

    host = _host(store)
    old = utcnow() - timedelta(days=40)
    inventory.record(
        store,
        host.id,
        {
            "url": host.url,
            "name": host.name,
            "scanned_at": utcnow().isoformat(),
            "wordpress": "6.4.1",
            "themes": {},
            "plugins": {
                "so-no-admin": {
                    "version": "2.0",
                    "latest": None,
                    "seen_at": (utcnow() - timedelta(days=3)).isoformat(),
                },
                "removido": {"version": "1.0", "latest": None, "seen_at": old.isoformat()},
            },
        },
    )
    raw = copy.deepcopy(enumerated)
    assert inventory.carry_over(store, host.id, raw, 30) == 1
    assert "so-no-admin" in raw["plugins"] and "removido" not in raw["plugins"]
    assert raw["plugins"]["so-no-admin"]["version"] == {"number": "2.0"}
    entry = inventory.site_entry(raw, url=host.url, name=host.name, vulns=0, mode="partilhado")
    assert entry["plugins"]["so-no-admin"]["seen_at"].startswith((utcnow() - timedelta(days=3)).date().isoformat())
