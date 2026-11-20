"""Os índices do JsonStore dão sempre o mesmo resultado que uma pesquisa completa."""

from __future__ import annotations

import random
from datetime import timedelta

from vulnflux.models import Host, Run, RunStatus, Source, utcnow
from vulnflux.store import JsonStore


def _naive(runs, host_id=None, source=None, statuses=None):
    out = [
        r
        for r in runs.values()
        if (host_id is None or r.host_id == host_id)
        and (source is None or r.source == source)
        and (statuses is None or r.status in statuses)
    ]
    return sorted(out, key=lambda r: (r.created_at, r.id), reverse=True)


def test_indices_coincidem_com_pesquisa_completa(tmp_path):
    rnd = random.Random(7)  # noqa: S311 - dados de teste reprodutíveis
    store = JsonStore(tmp_path)
    hosts = [Host(name=f"h{i}.exemplo.pt", url=f"https://h{i}.exemplo.pt/") for i in range(4)]
    truth: dict[str, Run] = {}
    now = utcnow()
    for step in range(400):
        op = rnd.random()
        if op < 0.6 or not truth:
            h = rnd.choice(hosts)
            r = Run(
                host_id=h.id,
                host_name=h.name,
                source=rnd.choice([Source.WPSCAN, Source.GREENBONE]),
                status=rnd.choice(list(RunStatus)),
                created_at=now - timedelta(minutes=rnd.randint(0, 5000)),
            )
        else:  # atualizar uma existente (muda o estado, às vezes a data)
            r = truth[rnd.choice(list(truth))].model_copy(deep=True)
            r.status = rnd.choice(list(RunStatus))
            if rnd.random() < 0.2:
                r.created_at = now - timedelta(minutes=rnd.randint(0, 5000))
        store.save_run(r)
        truth[r.id] = r
        if step % 97 == 0:
            store.purge_older_than(3)  # 3 dias: apaga parte
            truth = {
                k: v for k, v in truth.items() if not (v.created_at < now - timedelta(days=3) and v.status.finished)
            }

    for h in hosts:
        for src in (Source.WPSCAN, Source.GREENBONE, None):
            for sts in (None, [RunStatus.SUCCESS, RunStatus.WARNING]):
                expected = [r.id for r in _naive(truth, h.id, src, set(sts) if sts else None)]
                got = [r.id for r in store.list_runs(host_id=h.id, source=src, statuses=sts)]
                assert got == expected
                assert store.count_runs(host_id=h.id, source=src, statuses=sts) == len(expected)
                if src is not None:
                    last = store.last_run(h.id, src, good_only=bool(sts))
                    assert (last.id if last else None) == (expected[0] if expected else None)
    assert [r.id for r in store.list_runs(limit=10, offset=5)] == [r.id for r in _naive(truth)][5:15]
    latest = store.latest_matrix()
    for (hid, src), run in latest.items():
        assert run.id == _naive(truth, hid, src)[0].id
    # e depois de recarregar do disco
    again = JsonStore(tmp_path)
    assert [r.id for r in again.list_runs()] == [r.id for r in _naive(truth)]
