"""Ponto de entrada: `python -m vulnflux` ou `vulnflux`."""

from __future__ import annotations

import logging
import os

import uvicorn


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("VF_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    from vulnflux.web.app import create_app

    # Um único processo: o agendador e as filas vivem dentro dele.
    uvicorn.run(
        create_app(),
        host=os.environ.get("VF_HOST", "0.0.0.0"),  # noqa: S104 - dentro do container, atrás do proxy
        port=int(os.environ.get("VF_PORT", "8080")),
        workers=1,
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("VF_FORWARDED_ALLOW_IPS", "127.0.0.1"),
        access_log=False,
    )


if __name__ == "__main__":
    main()
