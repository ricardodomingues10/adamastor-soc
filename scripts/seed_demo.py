"""Gera dados de demonstração num data_dir (para ver a interface sem scanners).

Uso:  python scripts/seed_demo.py /tmp/vf-demo
Nunca apontar para o data_dir de produção.
"""

from __future__ import annotations

import random
import sys
from datetime import timedelta
from pathlib import Path

from vulnflux.errors import ErrorKind
from vulnflux.models import Host, Run, RunStatus, Source, Step, StepStatus, Trigger, utcnow
from vulnflux.store import JsonStore

HOSTS = [
    ("www.exemplo.pt", "Sites_Publicos_PRD", True, True),
    ("jogos.exemplo.pt", "Apps_Publicas_Jogos_TST", True, False),
    ("noticias.exemplo.pt", "Sites_Publicos_PRD", True, True),
    ("intranet.exemplo.pt", "Development", True, False),
    ("loja.exemplo.pt", "Sites_Publicos_TST", True, True),
    ("eventos.exemplo.pt", "Sites_Publicos_PRD", True, False),
    ("api.exemplo.pt", "Sites_Publicos_PRD", False, True),
    ("blog.exemplo.pt", "Sites_Publicos_TST", True, False),
]

WP_STEPS = ["Preparar", "Scan", "Validar", "Converter", "Gate", "Importar no DefectDojo"]
GB_STEPS = ["Preparar task", "Scan", "Recolher report", "Validar", "Gate", "Importar no DefectDojo"]


def main(data_dir: str) -> None:
    rnd = random.Random(7)  # noqa: S311 - dados de demonstração
    store = JsonStore(Path(data_dir))
    now = utcnow()
    for name, env, wp, gb in HOSTS:
        host = store.get_host_by_name(name) or Host(
            name=name,
            url=f"https://{name}/" if wp else None,
            environment=env,
            wpscan_enabled=wp,
            greenbone_enabled=gb,
            tags=rnd.sample(["avada", "prioritario", "externo"], k=rnd.randint(0, 2)),
        )
        store.save_host(host)
        for source, steps in ((Source.WPSCAN, WP_STEPS), (Source.GREENBONE, GB_STEPS)):
            if not host.source_enabled(source):
                continue
            for i in range(rnd.randint(2, 6)):
                created = now - timedelta(days=i * (1 if source is Source.WPSCAN else 30), hours=rnd.randint(0, 20))
                status = rnd.choices(
                    [RunStatus.SUCCESS, RunStatus.WARNING, RunStatus.FAILED, RunStatus.SKIPPED], [70, 8, 15, 7]
                )[0]
                run = Run(
                    host_id=host.id,
                    host_name=host.name,
                    source=source,
                    trigger=Trigger.SCHEDULE,
                    status=status,
                    created_at=created,
                    started_at=created,
                    finished_at=created + timedelta(minutes=rnd.randint(2, 50)),
                )
                total = rnd.randint(0, 25)
                sev = {
                    "Critical": rnd.randint(0, 2),
                    "High": rnd.randint(0, 5),
                    "Medium": rnd.randint(0, 9),
                    "Low": rnd.randint(0, 6),
                    "Info": 0,
                }
                sev["Info"] = max(0, total - sum(sev.values()))
                n_ok = len(steps) if status.good else rnd.randint(1, 3)
                for j, sname in enumerate(steps[:n_ok]):
                    st = Step(
                        name=sname,
                        status=StepStatus.OK,
                        started_at=created + timedelta(minutes=j),
                        finished_at=created + timedelta(minutes=j + 1),
                        detail="",
                    )
                    if not status.good and j == n_ok - 1:
                        st.status = StepStatus.FAILED
                    run.steps.append(st)
                if status.good:
                    run.stats = {
                        "findings_total": sum(sev.values()),
                        "by_severity": sev,
                        "close_old_findings": True,
                        "dd": {
                            "test_id": rnd.randint(100, 900),
                            "created": rnd.randint(0, 3),
                            "closed": rnd.randint(0, 2),
                            "reactivated": 0,
                            "untouched": total,
                        },
                    }
                    if status is RunStatus.WARNING:
                        run.warnings = ["queda de 80% nos findings (20 → 4): importado sem fechar findings antigos"]
                        run.stats["close_old_findings"] = False
                else:
                    kind, msg = rnd.choice(
                        [
                            (ErrorKind.DATA, "API do WPScan: sem dados de vulnerabilidades"),
                            (ErrorKind.TRANSIENT, "WPScan excedeu 1800s"),
                            (ErrorKind.DEPENDENCY, "DefectDojo inacessível: ConnectionError"),
                            (ErrorKind.QUOTA, "quota WPScan baixa (2 < 5)"),
                            (
                                ErrorKind.PERMANENT,
                                "scan abortado: The remote website is up, but does not seem to be running WordPress.",
                            ),
                        ]
                    )
                    run.error_kind, run.error_message = kind, msg
                store.save_run(run)
    store.set_state(
        "health",
        {
            "defectdojo": {
                "label": "DefectDojo",
                "status": "ok",
                "message": "84 ms · 23 products",
                "checked_at": now.isoformat(),
                "details": {},
            },
            "wpscan_api": {
                "label": "API WPScan",
                "status": "warn",
                "message": "plano free · 4/25 pedidos",
                "checked_at": now.isoformat(),
                "details": {"requests_remaining": 4},
            },
            "wpscan_cli": {
                "label": "CLI WPScan",
                "status": "ok",
                "message": "Version: 4.2.0",
                "checked_at": now.isoformat(),
                "details": {},
            },
            "greenbone": {
                "label": "Greenbone",
                "status": "ok",
                "message": "parado (on-demand)",
                "checked_at": now.isoformat(),
                "details": {},
            },
        },
    )
    print(f"dados de demonstração em {data_dir}: {len(store.list_hosts())} hosts, {store.count_runs()} execuções")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "vf-demo-data")
