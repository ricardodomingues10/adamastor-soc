"""Ponto de entrada.

soc-portal                 arranca a interface (porta 8080 dentro do container)
soc-portal check [--json]  corre todas as verificações uma vez e mostra o resultado
                           (diagnóstico e CI; código de saída 1 se a config for inválida)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

import uvicorn


def _check(as_json: bool) -> int:
    from socportal.config import get_settings
    from socportal.monitor import Monitor

    settings = get_settings()
    monitor = Monitor(settings)
    if monitor.registry.error:
        print(f"portal.yaml inválido: {monitor.registry.error}", file=sys.stderr)
        return 1
    monitor.run_once()
    if as_json:
        out = {
            "services": {k: v.to_dict() for k, v in monitor.states.items()},
            "freshness": monitor.freshness(),
            "edges": monitor.edges(),
            "versions": {s.id: monitor.latest_for(s) for s in monitor.config.services},
        }
        print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
        return 0
    for s in monitor.config.services:
        st = monitor.state(s.id)
        latest = (monitor.latest_for(s) or {}).get("version")
        ver = st.version or "?"
        if latest:
            ver += f" (última {latest})"
        print(f"{st.status.upper():8} {s.name:24} {ver:28} {st.message}")
    for f in monitor.freshness():
        age = f"{f['age_hours']} h" if f.get("age_hours") is not None else "?"
        print(f"  {f['status'].upper():6} {f['service_name']}/{f.get('name', f.get('id'))}: {age}")
    return 0


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("SP_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser(prog="soc-portal")
    sub = parser.add_subparsers(dest="cmd")
    chk = sub.add_parser("check", help="verifica todos os serviços uma vez")
    chk.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.cmd == "check":
        sys.exit(_check(args.json))

    from socportal.web.app import create_app

    uvicorn.run(
        create_app(),
        host=os.environ.get("SP_HOST", "0.0.0.0"),  # noqa: S104 - dentro do container
        port=int(os.environ.get("SP_LISTEN_PORT", "8080")),
        workers=1,
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("SP_FORWARDED_ALLOW_IPS", "127.0.0.1"),
        access_log=False,
    )


if __name__ == "__main__":
    main()
