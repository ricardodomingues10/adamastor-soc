"""Disparos simultâneos (agendamento + botão, fim de anel + portões) não duplicam trabalho.

A escrita é atrasada de propósito para abrir a janela entre ler e gravar.
"""

from __future__ import annotations

import threading
import time

from vulnflux.models import Host, Source, Trigger
from vulnflux.pipeline import create_run
from vulnflux.servers import cycles
from vulnflux.store import JsonStore


def _slow(store: JsonStore) -> JsonStore:
    for name in ("save_cycle", "save_run"):
        original = getattr(store, name)

        def slow(*a, _o=original, **k):
            time.sleep(0.15)
            return _o(*a, **k)

        setattr(store, name, slow)
    return store


def _twice(fn):
    out: list = []
    threads = [threading.Thread(target=lambda: out.append(fn())) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return out


def _server(store: JsonStore) -> Host:
    host = Host(
        name="srv1.exemplo.pt",
        ssh_enabled=True,
        ssh_host="10.0.0.1",
        ssh_user="vulnflux",
        patch_mode="seguranca",
        patch_ring=1,
    )
    store.save_host(host)
    return host


def test_dois_ciclos_simultaneos_criam_um_so(settings, tmp_path):
    store = _slow(JsonStore(tmp_path))
    _server(store)
    results = _twice(lambda: cycles.new_cycle(store, settings, Trigger.MANUAL))
    assert sum(1 for r in results if r) == 1
    assert sum(1 for c in store.list_cycles() if c.get("status") == cycles.ACTIVE) == 1


def test_anel_nao_arranca_duas_vezes(settings, tmp_path):
    settings.patch_ring3_approval = False
    settings.patch_soak_hours = 0
    store = _slow(JsonStore(tmp_path))
    _server(store)
    cycles.new_cycle(store, settings, Trigger.MANUAL)
    starts: list = []
    _twice(lambda: cycles.advance(store, settings, lambda cid, idx: starts.append(idx)))
    assert starts == [1]


def test_execucao_nao_duplicada(tmp_path):
    store = _slow(JsonStore(tmp_path))
    host = Host(name="www.exemplo.pt", url="https://www.exemplo.pt/")
    store.save_host(host)
    runs = _twice(lambda: create_run(store, host, Source.WPSCAN, Trigger.MANUAL))
    assert sum(1 for r in runs if r) == 1
