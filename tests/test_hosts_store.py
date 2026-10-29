from __future__ import annotations

import json
from datetime import timedelta

import pytest

from vulnflux.errors import ErrorKind
from vulnflux.hosts import HostValidationError, host_from_form, normalize_name, normalize_url, parse_bulk
from vulnflux.models import Host, Run, RunStatus, Source, utcnow
from vulnflux.store import DuplicateHostError, JsonStore

# ------------------------------------------------------------------ normalização


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://WWW.Exemplo.pt/noticias?x=1", "www.exemplo.pt"),
        ("www.exemplo.pt", "www.exemplo.pt"),
        ("www.exemplo.pt:8443/path", "www.exemplo.pt"),
        ("10.0.0.5", "10.0.0.5"),
        ("exemplo.pt.", "exemplo.pt"),
    ],
)
def test_normalize_name(raw, expected):
    assert normalize_name(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "não válido", "-mau.pt", "a..b"])
def test_normalize_name_invalido(raw):
    with pytest.raises(ValueError):
        normalize_name(raw)


def test_normalize_url():
    assert normalize_url("www.exemplo.pt") == "https://www.exemplo.pt/"
    assert normalize_url("HTTP://Exemplo.PT/blog") == "http://exemplo.pt/blog"
    assert normalize_url("") is None
    with pytest.raises(ValueError):
        normalize_url("ftp://exemplo.pt")


def test_form_deriva_nome_do_url_e_valida_fontes():
    host = host_from_form(
        {
            "url": "https://Loja.Exemplo.pt/",
            "wpscan_enabled": "on",
            "greenbone_enabled": "off",
            "enabled": "on",
            "tags": "Avada, avada prioritario",
        }
    )
    assert host.name == "loja.exemplo.pt"
    assert host.tags == ["avada", "prioritario"]
    assert host.scan_target is None

    with pytest.raises(HostValidationError) as exc:
        host_from_form({"url": "", "name": "x.pt", "wpscan_enabled": "on"})
    assert "url" in exc.value.errors

    with pytest.raises(HostValidationError) as exc:
        host_from_form({"name": "x.pt", "wpscan_enabled": "off", "greenbone_enabled": "off"})
    assert "sources" in exc.value.errors


def test_form_url_invalido_nao_duplica_erro_no_nome():
    with pytest.raises(HostValidationError) as exc:
        host_from_form({"url": "ftp://mau", "wpscan_enabled": "on"})
    assert "url" in exc.value.errors and "name" not in exc.value.errors
    assert "http" in exc.value.errors["url"]


def test_form_checkbox_desligado_desativa():
    existing = Host(name="a.pt", url="https://a.pt/")
    updated = host_from_form({"url": "https://a.pt/", "wpscan_enabled": "on", "enabled": "off"}, existing)
    assert updated.enabled is False and updated.id == existing.id


def test_bulk():
    text = """
    # comentário
    https://a.exemplo.pt/
    b.exemplo.pt ; Development ; interno
    https://A.exemplo.pt/outra
    existente.pt
    """
    res = parse_bulk(text, default_environment="PRD", wpscan=True, greenbone=False, existing_names={"existente.pt"})
    assert [h.name for h in res.hosts] == ["a.exemplo.pt", "b.exemplo.pt"]
    assert res.hosts[1].environment == "Development" and res.hosts[1].tags == ["interno"]
    assert set(res.duplicates) == {"a.exemplo.pt", "existente.pt"}
    assert not res.errors

    res = parse_bulk("isto não!", default_environment="PRD", wpscan=True, greenbone=False, existing_names=set())
    assert res.errors and "linha 1" in res.errors[0]


# ------------------------------------------------------------------ armazenamento


def test_store_persistencia_e_duplicados(settings, store):
    h = store.save_host(Host(name="a.pt", url="https://a.pt/"))
    with pytest.raises(DuplicateHostError):
        store.save_host(Host(name="a.pt"))
    reloaded = JsonStore(settings.data_dir)
    assert reloaded.get_host(h.id).name == "a.pt"
    data = json.loads((settings.data_dir / "hosts.json").read_text())
    assert data["version"] == 1 and len(data["hosts"]) == 1
    # nenhum ficheiro temporário deixado para trás
    assert not list(settings.data_dir.glob(".hosts.json.*"))


def test_store_runs_e_recuperacao(settings, store):
    h = store.save_host(Host(name="a.pt", url="https://a.pt/"))
    old = Run(
        host_id=h.id,
        host_name=h.name,
        source=Source.WPSCAN,
        status=RunStatus.SUCCESS,
        stats={"findings_total": 7},
        created_at=utcnow() - timedelta(days=2),
    )
    store.save_run(old)
    running = store.save_run(Run(host_id=h.id, host_name=h.name, source=Source.WPSCAN, status=RunStatus.RUNNING))
    assert store.active_run(h.id, Source.WPSCAN).id == running.id
    assert store.last_run(h.id, Source.WPSCAN, good_only=True).findings_total == 7

    reloaded = JsonStore(settings.data_dir)
    assert reloaded.recover_interrupted() == 1
    r = reloaded.get_run(running.id)
    assert r.status is RunStatus.INTERRUPTED and r.error_kind is ErrorKind.TRANSIENT
    assert reloaded.active_run(h.id, Source.WPSCAN) is None


def test_store_purga(store):
    h = store.save_host(Host(name="a.pt"))
    r = store.save_run(
        Run(
            host_id=h.id,
            host_name=h.name,
            source=Source.GREENBONE,
            status=RunStatus.FAILED,
            created_at=utcnow() - timedelta(days=400),
        )
    )
    store.write_artifact(r.id, "x.json", b"{}")
    assert store.purge_older_than(180) == 1
    assert store.get_run(r.id) is None
    assert not (store.artifacts_dir / r.id).exists()


def test_artefactos_sem_path_traversal(store):
    store.write_artifact("abc123", "raw.json", b"{}")
    assert store.artifact_path("abc123", "raw.json") is not None
    for bad in ["../hosts.json", "..", ".hidden", "a/b"]:
        assert store.artifact_path("abc123", bad) is None
    assert store.artifact_path("..", "hosts.json") is None
    with pytest.raises(ValueError):
        store.write_artifact("abc123", "../x", b"")
