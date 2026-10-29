"""Ferramentas do ambiente de laboratório (compose.lab.yaml). Não usado em produção.

    python -m vulnflux.labtools dd-token
    python -m vulnflux.labtools risk [--no-download]

dd-token: espera que o DefectDojo do laboratório responda, obtém o token da API do
admin (endpoint api-token-auth) e grava-o em /run/secrets/vf_dd_token, onde o VulnFlux
o lê como VF_DD_TOKEN.

risk: pede ao VulnFlux em execução (http://127.0.0.1:8080, dentro do container) que
recalcule as prioridades, espera pelo fim e mostra o resultado. Passa pela interface
web (login + CSRF) porque o VulnFlux é de processo único: o estado vive nesse processo.
"""

from __future__ import annotations

import json
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


def trigger_risk(base: str, username: str, password: str, *, download: bool = True, timeout_s: int = 1800) -> int:
    import re

    s = requests.Session()
    page = s.get(f"{base}/login", timeout=15)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    if not token:
        print("página de login sem token CSRF", file=sys.stderr)
        return 1
    resp = s.post(
        f"{base}/login",
        data={"username": username, "password": password, "csrf_token": token.group(1), "next": "/"},
        allow_redirects=False,
        timeout=15,
    )
    if resp.status_code != 303:
        print(f"login falhou ({resp.status_code})", file=sys.stderr)
        return 1
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', s.get(f"{base}/risk", timeout=15).text)
    resp = s.post(
        f"{base}/actions/risk",
        params={"download": "1" if download else "0"},
        headers={"X-CSRF-Token": csrf.group(1) if csrf else "", "HX-Request": "true"},
        timeout=30,
    )
    run_id = resp.headers.get("X-Run-Id")
    if resp.status_code != 204 or not run_id:
        print(f"não foi possível iniciar ({resp.status_code}): já há um cálculo em curso?", file=sys.stderr)
        return 1
    print(f"execução {run_id} iniciada", flush=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        run = s.get(f"{base}/runs/{run_id}.json", timeout=15).json()
        if run["status"] not in ("queued", "running"):
            for step in run.get("steps", []):
                print(f"  {step['status']:8} {step['name']}: {step.get('detail', '')}")
            for w in run.get("warnings", []):
                print(f"  aviso: {w}")
            if run.get("error_message"):
                print(f"  erro: {run['error_message']}")
            print(json.dumps({"status": run["status"], **run.get("stats", {})}, ensure_ascii=False))
            return 0 if run["status"] in ("success", "warning") else 1
        time.sleep(3)
    print("o cálculo não terminou a tempo", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if argv[:1] == ["risk"]:
        return trigger_risk(
            os.environ.get("LAB_VF_URL", "http://127.0.0.1:8080"),
            os.environ.get("VF_ADMIN_USER", "admin"),
            os.environ["VF_ADMIN_PASSWORD"],
            download="--no-download" not in argv,
        )
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
