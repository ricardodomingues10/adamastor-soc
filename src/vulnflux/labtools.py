"""Ferramentas do ambiente de laboratório (compose.lab.yaml). Não usado em produção.

    python -m vulnflux.labtools dd-token
    python -m vulnflux.labtools risk [--no-download]
    python -m vulnflux.labtools add-server NOME ENDEREÇO [anel] [modo]
    python -m vulnflux.labtools bootstrap [verificar|atualizar]
    python -m vulnflux.labtools gb-scan NOME ALVO [rapido|completo] [minutos]

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


def _session(base: str, username: str, password: str):
    import re

    s = requests.Session()
    page = s.get(f"{base}/login", timeout=15)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    resp = s.post(
        f"{base}/login",
        data={"username": username, "password": password, "csrf_token": token.group(1) if token else "", "next": "/"},
        allow_redirects=False,
        timeout=15,
    )
    if resp.status_code != 303:
        raise SystemExit(f"login falhou ({resp.status_code})")
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', s.get(f"{base}/servers", timeout=15).text)
    s.headers.update({"X-CSRF-Token": csrf.group(1) if csrf else "", "HX-Request": "true"})
    return s


def add_server(
    base: str,
    username: str,
    password: str,
    name: str,
    address: str,
    ring: str = "0",
    mode: str = "seguranca",
    *,
    timeout_s: int = 300,
) -> int:
    """Regista (ou atualiza) um servidor e corre a primeira verificação, à espera do resultado."""
    s = _session(base, username, password)
    hosts = s.get(f"{base}/hosts/export.json", timeout=15).json()
    hosts = hosts.get("hosts", hosts) if isinstance(hosts, dict) else hosts
    existing = next((h for h in hosts if h["name"] == name), None)
    form = {
        "name": name,
        "url": "",
        "environment": "Laboratorio",
        "wpscan_enabled": "off",
        "greenbone_enabled": "off",
        "ssh_enabled": "on",
        "enabled": "on",
        "ssh_address": address,
        "ssh_port": "22",
        "ssh_user": "vulnflux",
        "patch_ring": ring,
        "patch_mode": mode,
        "patch_reboot": "off",
        "lynis": "off",
        "criticality": "baixo",
        "exposure": "interno",
        "data_class": "interno",
        "tags": "laboratorio",
        "notes": "servidor de demonstração",
    }
    resp = s.post(f"{base}/hosts/{existing['id']}" if existing else f"{base}/hosts", data=form, timeout=15)
    if resp.status_code not in (200, 204):
        print(f"não foi possível gravar o servidor ({resp.status_code}): {resp.text[:300]}", file=sys.stderr)
        return 1
    hosts = s.get(f"{base}/hosts/export.json", timeout=15).json()
    hosts = hosts.get("hosts", hosts) if isinstance(hosts, dict) else hosts
    host = next(h for h in hosts if h["name"] == name)
    print(f"servidor {name} ({address}) gravado: anel {ring}, modo {mode}", flush=True)
    resp = s.post(f"{base}/servers/{host['id']}/check", timeout=15)
    run_id = resp.headers.get("X-Run-Id")
    if not run_id:
        print(f"verificação não iniciada ({resp.status_code})", file=sys.stderr)
        return 1
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
            print(f"resultado: {base.replace('127.0.0.1:8080', 'localhost')}/servers/{host['id']}")
            return 0 if run["status"] in ("success", "warning") else 1
        time.sleep(3)
    print("a verificação não terminou a tempo", file=sys.stderr)
    return 1


def _hosts(s, base: str) -> list[dict]:
    data = s.get(f"{base}/hosts/export.json", timeout=15).json()
    return data.get("hosts", data) if isinstance(data, dict) else data


def wait_run(s, base: str, run_id: str, timeout_s: int, *, every: int = 20) -> dict:
    """Espera pelo fim de uma execução, mostrando o passo atual quando muda."""
    deadline, last = time.monotonic() + timeout_s, ""
    while time.monotonic() < deadline:
        run = s.get(f"{base}/runs/{run_id}.json", timeout=30).json()
        cur = next((st for st in reversed(run.get("steps", [])) if st["status"] == "running"), None)
        line = f"{cur['name']}: {cur.get('detail', '')}" if cur else run["status"]
        if line != last:
            print(f"  [{time.strftime('%H:%M:%S')}] {line}", flush=True)
            last = line
        if run["status"] not in ("queued", "running"):
            return run
        time.sleep(every)
    return {"status": "timeout", "steps": [], "stats": {}}


def gb_scan(
    base: str, username: str, password: str, name: str, target: str, profile: str = "rapido", minutes: int = 240
) -> int:
    """Regista (ou atualiza) um host só para o Greenbone, corre o scan e mostra a duração e os achados."""
    s = _session(base, username, password)
    existing = next((h for h in _hosts(s, base) if h["name"] == name), None)
    form = {
        "name": name,
        "url": "",
        "scan_target": target,
        "environment": "Laboratorio",
        "wpscan_enabled": "off",
        "greenbone_enabled": "on",
        "enabled": "on",
        "greenbone_profile": profile,
        "criticality": "alto",
        "exposure": "interno",
        "data_class": "interno",
        "tags": "laboratorio,alvo-vulneravel",
        "notes": "alvo de laboratório com vulnerabilidades conhecidas",
    }
    resp = s.post(f"{base}/hosts/{existing['id']}" if existing else f"{base}/hosts", data=form, timeout=15)
    if resp.status_code not in (200, 204):
        print(f"não foi possível gravar o host ({resp.status_code}): {resp.text[:300]}", file=sys.stderr)
        return 1
    host = next(h for h in _hosts(s, base) if h["name"] == name)
    resp = s.post(f"{base}/hosts/{host['id']}/run/greenbone", timeout=30)
    run_id = resp.headers.get("X-Run-Id")
    if not run_id:
        print(f"scan não iniciado ({resp.status_code}): {resp.headers.get('HX-Trigger', '')}", file=sys.stderr)
        return 1
    print(f"scan Greenbone {run_id}: {name} → {target}, perfil {profile}", flush=True)
    run = wait_run(s, base, run_id, minutes * 60)
    scan = next((st for st in run.get("steps", []) if st["name"] == "Scan"), None)
    scan_s = None
    if scan and scan.get("started_at") and scan.get("finished_at"):
        from datetime import datetime

        scan_s = (
            datetime.fromisoformat(scan["finished_at"]) - datetime.fromisoformat(scan["started_at"])
        ).total_seconds()
    for st in run.get("steps", []):
        print(f"  {st['status']:8} {st['name']}: {st.get('detail', '')}")
    out = {
        "status": run["status"],
        "profile": profile,
        "scan_minutes": round(scan_s / 60, 1) if scan_s else None,
        "by_severity": run.get("stats", {}).get("by_severity"),
        "findings": run.get("stats", {}).get("findings_total"),
        "cvss9": run.get("stats", {}).get("cvss9"),
        "top": run.get("stats", {}).get("top", [])[:12],
        "error": run.get("error_message"),
    }
    print(json.dumps(out, ensure_ascii=False), flush=True)
    return 0 if run["status"] in ("success", "warning") else 1


def main(argv: list[str]) -> int:
    if argv[:1] == ["gb-scan"] and len(argv) >= 3:
        args = argv[1:]
        return gb_scan(
            os.environ.get("LAB_VF_URL", "http://127.0.0.1:8080"),
            os.environ.get("VF_ADMIN_USER", "admin"),
            os.environ["VF_ADMIN_PASSWORD"],
            args[0],
            args[1],
            args[2] if len(args) > 2 else "rapido",
            int(args[3]) if len(args) > 3 else 240,
        )
    if argv[:1] == ["add-server"] and len(argv) >= 3:
        return add_server(
            os.environ.get("LAB_VF_URL", "http://127.0.0.1:8080"),
            os.environ.get("VF_ADMIN_USER", "admin"),
            os.environ["VF_ADMIN_PASSWORD"],
            *argv[1:5],
        )
    if argv[:1] == ["bootstrap"]:
        from vulnflux.config import get_settings
        from vulnflux.servers import bootstrap, ssh

        mode = argv[1] if len(argv) > 1 else "verificar"
        print(bootstrap.script(ssh.public_key(get_settings()), mode=mode))
        return 0
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
