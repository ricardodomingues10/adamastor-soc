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


BOM = """
title: T
services:
  - id: a
    name: A
    probes: [{type: http, url: "http://a.lab/"}]
  - id: b
    name: B
    probes: [{type: tcp, url: "b.lab:22"}]
"""


def test_servico_invalido_no_primeiro_arranque_nao_apaga_os_outros(tmp_path):
    """Um serviço com erro já não deixa o portal sem nenhum serviço."""
    path = tmp_path / "portal.yaml"
    path.write_text(BOM.replace('url: "b.lab:22"', 'url: "tcp://b.lab:22"'))
    r = Registry(path)
    assert [s.id for s in r.config.services] == ["a"]
    assert "b:" in r.error and "ignorado" in r.error


def test_servico_estragado_mantem_a_versao_anterior(tmp_path):
    path = tmp_path / "portal.yaml"
    path.write_text(BOM)
    r = Registry(path)
    assert r.error is None and len(r.config.services) == 2
    path.write_text(BOM.replace('url: "b.lab:22"', 'url: "tcp://b.lab:22"').replace("name: A", "name: A2"))
    os.utime(path, (os.path.getatime(path) + 5, os.path.getmtime(path) + 5))
    r.reload()
    assert r.config.get("a").name == "A2"  # a alteração válida entra
    assert r.config.get("b").probes[0].url == "b.lab:22"  # a inválida fica com a versão anterior
    assert "mantida a versão anterior" in r.error


def test_dependente_de_servico_ignorado_tambem_sai(tmp_path):
    path = tmp_path / "portal.yaml"
    text = (
        BOM.replace('url: "b.lab:22"', 'url: "tcp://b.lab:22"')
        + """  - id: c
    name: C
    depends_on: [b]
"""
    )
    path.write_text(text)
    r = Registry(path)
    assert [s.id for s in r.config.services] == ["a"]
    assert "c: depende" in r.error


def test_yaml_ilegivel_mantem_tudo(tmp_path):
    path = tmp_path / "portal.yaml"
    path.write_text(BOM)
    r = Registry(path)
    path.write_text("services: [ {")
    os.utime(path, (os.path.getatime(path) + 5, os.path.getmtime(path) + 5))
    r.reload()
    assert len(r.config.services) == 2 and "YAML inválido" in r.error
