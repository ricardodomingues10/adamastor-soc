"""Ferramentas do ambiente de laboratório (compose.lab.yaml). Não usado em produção.

    python -m vulnflux.labtools dd-token

Espera que o DefectDojo do laboratório responda, obtém o token da API do admin
(endpoint api-token-auth) e grava-o em /run/secrets/vf_dd_token, onde o VulnFlux o
lê como VF_DD_TOKEN.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import requests


def dd_token(
    url: str,
    username: str,
    password: str,
    output: Path,
    *,
    timeout_s: int = 1800,
    interval_s: int = 10,
) -> int:
    endpoint = url.rstrip("/") + "/api/v2/api-token-auth/"
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        try:
            resp = requests.post(endpoint, data={"username": username, "password": password}, timeout=15)
            if resp.status_code == 200 and resp.json().get("token"):
                output.parent.mkdir(parents=True, exist_ok=True)
                tmp = output.with_suffix(".tmp")
                tmp.write_text(resp.json()["token"])
                tmp.chmod(0o644)  # lido pelo utilizador do VulnFlux (uid 10001)
                tmp.replace(output)
                print(f"token do DefectDojo gravado em {output}", flush=True)
                return 0
            if resp.status_code == 400:
                # DefectDojo já responde mas recusa as credenciais: esperar não resolve
                # se o initializer já terminou; damos margem para ainda estar a criar o admin.
                last = f"credenciais recusadas ({resp.text[:200]})"
            else:
                last = f"HTTP {resp.status_code}"
        except requests.RequestException as exc:
            last = exc.__class__.__name__
        print(f"à espera do DefectDojo em {url}: {last}", flush=True)
        time.sleep(interval_s)
    print(f"DefectDojo não respondeu em {timeout_s}s: {last}", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if argv[:1] != ["dd-token"]:
        print(__doc__)
        return 2
    return dd_token(
        os.environ.get("LAB_DD_URL", "http://dd-nginx:8080"),
        os.environ.get("LAB_DD_USER", "admin"),
        os.environ["LAB_DD_PASSWORD"],
        Path(os.environ.get("LAB_DD_TOKEN_FILE", "/run/secrets/vf_dd_token")),
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
