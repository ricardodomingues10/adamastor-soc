from __future__ import annotations

import os

import pytest

from socportal.registry import Registry, RegistryError, parse


def test_config_valida(config_file):
    reg = Registry(config_file)
    assert reg.error is None
    assert [s.id for s in reg.config.services] == ["vulnflux", "greenbone", "defectdojo"]
    assert reg.config.groups()[0][0] == "Vulnerabilidades"


def test_dependencia_inexistente():
    with pytest.raises(RegistryError, match="depends_on 'nada'"):
        parse("services:\n  - {id: a, name: A, depends_on: [nada]}\n")


def test_ids_repetidos():
    with pytest.raises(RegistryError, match="ids repetidos: a"):
        parse("services:\n  - {id: a, name: A}\n  - {id: a, name: B}\n")


def test_probe_sem_url_e_campos_desconhecidos():
    with pytest.raises(RegistryError, match="precisa de 'url'"):
        parse("services:\n  - {id: a, name: A, probes: [{type: http}]}\n")
    with pytest.raises(RegistryError, match="Extra inputs"):
        parse("services:\n  - {id: a, name: A, password: x}\n")


def test_componente_de_servico_inexistente():
    with pytest.raises(RegistryError, match="soc-component"):
        parse("services:\n  - {id: a, name: A, probes: [{type: soc-component, service: b, component: c}]}\n")


def test_expande_variaveis(monkeypatch):
    monkeypatch.setenv("DD_PORT", "18999")
    cfg = parse(
        "services:\n  - {id: a, name: A, link: 'http://localhost:${DD_PORT:-8081}'}\n"
        "  - {id: b, name: B, link: 'http://localhost:${NAO_EXISTE:-8090}'}\n"
    )
    assert cfg.services[0].link == "http://localhost:18999"
    assert cfg.services[1].link == "http://localhost:8090"


def test_ficheiro_invalido_mantem_a_ultima_config_boa(config_file):
    reg = Registry(config_file)
    config_file.write_text("services: [ {id: a")
    os.utime(config_file, (1, 1))  # força mtime diferente
    assert reg.reload() is False
    assert "YAML inválido" in reg.error
    assert len(reg.config.services) == 3  # continua com a anterior


def test_token_lido_do_ficheiro_ou_env(config_file, token_file, monkeypatch):
    monkeypatch.setenv("TEST_VF_TOKEN", "abc")
    reg = Registry(config_file)
    assert reg.config.get("defectdojo").probes[0].token() == "dd-secret"
    assert reg.config.get("vulnflux").probes[0].token() == "abc"
    token_file.unlink()
    assert reg.config.get("defectdojo").probes[0].token() is None
